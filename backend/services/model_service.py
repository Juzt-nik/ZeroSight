"""ML model service: loads or trains a baseline detector and provides inference.

P0-05: Uses a shared window-level feature extractor (detection/features.py)
for both training and inference, guaranteeing feature parity between
training and serving. Model metadata records dataset, feature version,
split strategy, and model version for reproducibility.
"""

import os
import json
import logging
import asyncio
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from detection.features import (
    WindowFeatureExtractor,
    FEATURE_VERSION as FEATURE_VERSION_STR,
)

# Record optional XGBoost availability, but the deployed baseline remains RF.
try:
    import xgboost as xgb  # noqa: F401
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

logger = logging.getLogger("vsoc.model_service")

if not XGBOOST_AVAILABLE:
    logger.info("XGBoost is unavailable; backend baseline uses RandomForestClassifier.")

CLASS_LABELS = ["Normal", "DoS", "Fuzzy", "Gear", "RPM"]

# Model metadata for provenance (P1-03, P1-04)
MODEL_METADATA_KEYS = [
    "dataset_version", "feature_version", "split_strategy",
    "model_version", "training_samples", "test_samples",
    "window_ms", "trained_at",
]

# P1-03: Ensemble configuration
USE_ENSEMBLE = os.getenv("USE_ENSEMBLE", "false").lower() in ("1", "true", "yes")
ISOLATION_FOREST_CONTAMINATION = float(os.getenv("ISOLATION_FOREST_CONTAMINATION", "0.1"))


class ModelService:
    def __init__(self, model_dir: str = "./models", dataset_dir: str = "./data/raw"):
        self.model_dir = Path(model_dir)
        self.dataset_dir = Path(dataset_dir)
        self.model: Optional[RandomForestClassifier] = None
        self.isolation_forest: Optional[IsolationForest] = None
        self.model_version: str = "0.1.0-window"
        self.is_trained: bool = False
        self.metrics: Optional[Dict[str, Any]] = None
        self._lock = asyncio.Lock()
        self.window_ms: float = 100.0
        self.feature_extractor: Optional[WindowFeatureExtractor] = None
        self.model_metadata: Dict[str, Any] = {}
        self.use_ensemble: bool = USE_ENSEMBLE

    def is_loaded(self) -> bool:
        return self.model is not None

    async def initialize(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
        model_path = self.model_dir / "baseline_rf.pkl"
        if_path = self.model_dir / "isolation_forest.pkl"
        metrics_path = self.model_dir / "metrics.json"
        metadata_path = self.model_dir / "metadata.json"

        # Initialize feature extractor
        self.feature_extractor = WindowFeatureExtractor(window_ms=self.window_ms)

        if model_path.exists():
            try:
                model = joblib.load(model_path)
                # P0-05: Validate feature-schema parity between saved artifact and extractor
                if metadata_path.exists():
                    with open(metadata_path) as f:
                        self.model_metadata = json.load(f)
                    saved_feature_names = self.model_metadata.get("feature_names", [])
                    reference_can_ids = self.model_metadata.get("reference_can_ids")
                    if reference_can_ids is None:
                        # Backward compatibility for artifacts created before
                        # reference IDs were stored explicitly.
                        reference_can_ids = [
                            name[len("per_id_count_"):]
                            for name in saved_feature_names
                            if name.startswith("per_id_count_")
                        ]
                    self.feature_extractor.reference_can_ids = set(reference_can_ids)
                    # Verify artifact hash if recorded
                    saved_hash = self.model_metadata.get("artifact_hash")
                    if saved_hash and model_path.exists():
                        actual_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
                        if actual_hash != saved_hash:
                            raise RuntimeError(
                                "Model artifact hash mismatch: expected %s, got %s. "
                                "Artifact may be corrupted or tampered."
                                % (saved_hash, actual_hash)
                            )
                    current_feature_names = self.feature_extractor.feature_names()
                    if saved_feature_names and saved_feature_names != current_feature_names:
                        raise RuntimeError(
                            "Feature-schema mismatch: saved artifact expects %d features "
                            "(%s) but extractor produces %d features (%s). "
                            "Retrain with the same feature configuration."
                            % (
                                len(saved_feature_names),
                                saved_feature_names[:5],
                                len(current_feature_names),
                                current_feature_names[:5],
                            )
                        )
                if self.use_ensemble and if_path.exists():
                    try:
                        self.isolation_forest = joblib.load(if_path)
                        logger.info("Loaded Isolation Forest from %s", if_path)
                    except Exception as exc:
                        logger.warning("Failed to load Isolation Forest: %s", exc)
                if metrics_path.exists():
                    with open(metrics_path) as f:
                        self.metrics = json.load(f)
                # All validation passed — assign the model and mark as trained
                self.model = model
                self.is_trained = True
                logger.info("Loaded existing model from %s", model_path)
                return
            except RuntimeError:
                # Re-raise schema/hash mismatch errors — don't swallow them
                raise
            except Exception as exc:
                logger.warning("Failed to load model: %s", exc)

        # No valid trained model available — fail safely, no dummy fallback
        raise RuntimeError(
            "No trained model found at %s. Train and save a model artifact first "
            "(see ZeroSight_ML_Pipeline.ipynb). The backend will not serve predictions "
            "without a valid trained model."
            % model_path
        )
    async def _train_baseline(self):
        """Train a RandomForest baseline from Car Hacking CSVs."""
        model_path = self.model_dir / "baseline_rf.pkl"
        if_path = self.model_dir / "isolation_forest.pkl"
        metrics_path = self.model_dir / "metrics.json"
        metadata_path = self.model_dir / "metadata.json"

        csv_files = [
            "DoS_dataset.csv", "Fuzzy_dataset.csv", "gear_dataset.csv",
            "RPM_dataset.csv", "normal_run_data.txt"
        ]
        label_map = {
            "DoS_dataset.csv": "DoS",
            "Fuzzy_dataset.csv": "Fuzzy",
            "gear_dataset.csv": "Gear",
            "RPM_dataset.csv": "RPM",
            "normal_run_data.txt": "Normal",
        }

        frames: List[pd.DataFrame] = []
        for fname in csv_files:
            fpath = self.dataset_dir / fname
            if not fpath.exists():
                logger.warning("Dataset file not found: %s", fpath)
                continue

            label = label_map[fname]
            df = self._load_can_csv(fpath, label)
            frames.append(df)
            logger.info("Loaded %s: %d rows, label=%s", fname, len(df), label)

        if not frames:
            raise RuntimeError(
                "No dataset files found in %s. Cannot train a model without "
                "HCRL Car-Hacking dataset. Expected: %s"
                % (self.dataset_dir, ", ".join(csv_files))
            )

        data = pd.concat(frames, ignore_index=True)
        logger.info("Total dataset: %d rows", len(data))

        # Engineer window-level features using shared extractor (P0-05)
        X, y, feature_names = self._engineer_features(data)

        # P1-04: Time-based split - contiguous segments, first 80% train, last 20% test
        split_idx = int(len(X) * 0.8)
        X_train, X_test = X[:split_idx], X[split_idx:]
        y_train, y_test = y[:split_idx], y[split_idx:]

        logger.info(
            "Train: %d samples, Test: %d samples (time-based split)",
            len(X_train), len(X_test),
        )

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        metrics = self._compute_metrics(y_test, y_pred, model.classes_)

        self.model = model
        self.is_trained = True
        self.metrics = metrics

        # Save model, metrics, and metadata
        joblib.dump(model, model_path)
        # Compute artifact hash for integrity verification
        model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        with open(metrics_path, "w") as f:
            json.dump(metrics, f, indent=2)

        self.model_metadata = {
            "dataset_version": "hcrl_car_hacking_v1",
            "feature_version": FEATURE_VERSION_STR,
            "split_strategy": "time_based_80_20",
            "model_version": self.model_version,
            "training_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "window_ms": self.window_ms,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "placeholder": False,
            "feature_names": feature_names,
            "reference_can_ids": sorted(self.feature_extractor.reference_can_ids),
            "artifact_hash": model_hash,
            "artifact_hash_algorithm": "sha256",
            "xgboost_available": XGBOOST_AVAILABLE,
            "model_algorithm": "RandomForestClassifier",
        }
        with open(metadata_path, "w") as f:
            json.dump(self.model_metadata, f, indent=2)

        logger.info(
            "Baseline trained: accuracy=%.4f, f1_macro=%.4f",
            metrics["accuracy"], metrics["f1_macro"],
        )

        # P1-03: Train Isolation Forest on normal windows for anomaly detection
        if self.use_ensemble:
            normal_mask = y_train == "Normal"
            if normal_mask.sum() > 0:
                X_normal = X_train[normal_mask]
                self.isolation_forest = IsolationForest(
                    contamination=ISOLATION_FOREST_CONTAMINATION,
                    random_state=42,
                    n_jobs=-1,
                )
                self.isolation_forest.fit(X_normal)
                joblib.dump(self.isolation_forest, if_path)
                logger.info(
                    "Isolation Forest trained on %d normal windows",
                    int(normal_mask.sum()),
                )
                self.model_metadata["ensemble"] = True
                self.model_metadata["isolation_forest_contamination"] = ISOLATION_FOREST_CONTAMINATION
                with open(metadata_path, "w") as f:
                    json.dump(self.model_metadata, f, indent=2)

    def _load_can_csv(self, fpath: Path, label: str) -> pd.DataFrame:
        rows = []
        with open(fpath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) < 4:
                    continue
                try:
                    timestamp = float(parts[0])
                    arbitration_id = parts[1]
                    dlc = int(parts[2])
                    data_bytes = []
                    if len(parts) > 4:
                        is_label = parts[-1] in ("R", "T", "A", "G", "F", "D",
                                                 "Normal", "DoS", "Fuzzy", "Gear", "RPM")
                        byte_parts = parts[3:-1] if is_label else parts[3:]
                        for b in byte_parts:
                            b = b.strip()
                            if b:
                                try:
                                    is_hex = all(c in "0123456789abcdefABCDEF" for c in b)
                                    data_bytes.append(int(b, 16) if is_hex else int(b))
                                except ValueError:
                                    data_bytes.append(0)
                    label_from_file = parts[-1] if len(parts) >= 4 and parts[-1] in (
                        "R", "T", "A", "G", "F", "D", "Normal", "DoS", "Fuzzy", "Gear", "RPM"
                    ) else label
                    rows.append({
                        "timestamp": timestamp,
                        "arbitration_id": arbitration_id,
                        "dlc": dlc,
                        "data_bytes": data_bytes,
                        "label": label_from_file if label_from_file in CLASS_LABELS else label,
                    })
                except (ValueError, IndexError):
                    continue
        return pd.DataFrame(rows)

    def _engineer_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Engineer window-level features from a DataFrame of CAN frames.

        P0-05: Uses WindowFeatureExtractor for shared feature computation.
        Frames are sorted by timestamp, grouped into windows, and each window
        produces one feature vector labeled by the majority class in the window.
        """
        if self.feature_extractor is None:
            self.feature_extractor = WindowFeatureExtractor(window_ms=self.window_ms)

        df = df.sort_values("timestamp").reset_index(drop=True)

        # Collect reference CAN IDs from the data
        ref_ids = set(df["arbitration_id"].unique().tolist())
        self.feature_extractor.reference_can_ids = ref_ids

        # Determine window boundaries from data
        if len(df) == 0:
            empty = np.zeros((1, len(self.feature_extractor.feature_names())))
            return empty, np.array(["Normal"]), self.feature_extractor.feature_names()

        timestamps_ms = df["timestamp"].values * 1000.0
        window_start = float(timestamps_ms.min())
        window_end = float(timestamps_ms.max())

        # Group frames into windows
        window_features: List[Dict[str, Any]] = []
        window_labels: List[str] = []

        current_start = window_start
        while current_start < window_end:
            current_end = current_start + self.window_ms
            mask = (timestamps_ms >= current_start) & (timestamps_ms < current_end)
            window_df = df[mask]

            if len(window_df) > 0:
                frames_list = window_df.to_dict("records")
                feats = self.feature_extractor.extract_window(
                    frames_list, current_start
                )
                # Majority label in window
                labels = window_df["label"].values
                majority_label = max(set(labels), key=list(labels).count)
                window_features.append(feats)
                window_labels.append(majority_label)

            current_start = current_end

        if not window_features:
            empty = np.zeros((1, len(self.feature_extractor.feature_names())))
            return empty, np.array(["Normal"]), self.feature_extractor.feature_names()

        feature_names = self.feature_extractor.feature_names()
        X = np.array([
            [float(f.get(name, 0.0)) for name in feature_names]
            for f in window_features
        ], dtype=np.float32)
        y = np.array(window_labels)
        return X, y, feature_names

    def _compute_metrics(self, y_true, y_pred, classes) -> Dict[str, Any]:
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
        rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
        f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
        cm = confusion_matrix(y_true, y_pred, labels=CLASS_LABELS)
        per_class = {}
        for i, cls in enumerate(CLASS_LABELS):
            cls_true = (y_true == cls)
            cls_pred = (y_pred == cls)
            tp = int(np.sum(cls_true & cls_pred))
            fp = int(np.sum(~cls_true & cls_pred))
            fn = int(np.sum(cls_true & ~cls_pred))
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1_cls = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            per_class[cls] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1_cls, 4),
                "support": int(np.sum(cls_true)),
            }
        return {
            "accuracy": round(float(acc), 4),
            "precision_macro": round(float(prec), 4),
            "recall_macro": round(float(rec), 4),
            "f1_macro": round(float(f1), 4),
            "per_class": per_class,
            "confusion_matrix": cm.tolist(),
            "classes": CLASS_LABELS,
            "training_samples": int(len(y_true) * 0.8),
            "test_samples": int(len(y_true) * 0.2),
        }

    def extract_features(self, frames: List[Dict[str, Any]]) -> np.ndarray:
        """Extract window-level features from a list of CAN frames.

        P0-05: Uses the shared WindowFeatureExtractor so training and serving
        produce identical feature names/order/values for identical windows.

        Args:
            frames: List of frame dicts with keys: timestamp, arbitration_id,
                dlc, data_bytes. All frames should fall within one window.

        Returns:
            Feature vector as a 2D numpy array (1 row, N features).
        """
        if self.feature_extractor is None:
            self.feature_extractor = WindowFeatureExtractor(window_ms=self.window_ms)

        if not frames:
            feature_names = self.feature_extractor.feature_names()
            return np.zeros((1, len(feature_names)), dtype=np.float32)

        # Use the earliest frame timestamp as window start
        timestamps = [f.get("timestamp", 0.0) for f in frames]
        window_start_ms = min(timestamps) * 1000.0 if timestamps else 0.0

        feats = self.feature_extractor.extract_window(frames, window_start_ms)
        feature_names = self.feature_extractor.feature_names()
        return self.feature_extractor.to_vector(feats, feature_names)

    async def predict_window(
        self, frames: List[Dict[str, Any]]
    ) -> Tuple[str, float, Dict[str, Any]]:
        """Predict on a window of CAN frames.

        Returns (prediction, confidence, features_dict).
        """
        async with self._lock:
            if not self.is_trained or self.model is None:
                raise RuntimeError("Model not trained or loaded")
            X = self.extract_features(frames)
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            confidence = float(np.max(probabilities))

            # P1-03: Ensemble - use Isolation Forest for anomaly scoring
            if self.use_ensemble and self.isolation_forest is not None:
                anomaly_score = self.isolation_forest.decision_function(X)[0]
                is_anomaly = self.isolation_forest.predict(X)[0] == -1
                if is_anomaly and prediction == "Normal":
                    prediction = "Anomaly"
                    confidence = float(max(confidence, abs(anomaly_score)))

            feature_names = self.feature_extractor.feature_names() if self.feature_extractor else []
            features_dict = {
                name: float(X[0][i]) for i, name in enumerate(feature_names)
            }
            return str(prediction), confidence, features_dict

    async def predict(self, frame_dict: Dict[str, Any]) -> Tuple[str, float]:
        """Predict on a single CAN frame (backward compatible).

        Wraps the single frame in a window and delegates to predict_window.
        """
        pred, conf, _ = await self.predict_window([frame_dict])
        return pred, conf

    async def predict_batch(self, frames: List[Dict[str, Any]]) -> List[Tuple[str, float]]:
        results = []
        for frame in frames:
            pred, conf = await self.predict(frame)
            results.append((pred, conf))
        return results

    def get_metrics(self) -> Optional[Dict[str, Any]]:
        return self.metrics


# Module-level singleton instance (initialized in main.py lifespan)
model_service = ModelService()
