"""ML model service: loads or trains a baseline detector and provides inference."""

import os
import json
import logging
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict, Any, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logger = logging.getLogger("vsoc.model_service")

FEATURE_COLUMNS = [
    "timestamp_delta_ms",
    "dlc",
    "byte_entropy",
    "can_id_freq",
    "data_byte_mean",
    "data_byte_std",
    "data_byte_min",
    "data_byte_max",
    "is_multi_byte",
]

CLASS_LABELS = ["Normal", "DoS", "Fuzzy", "Gear", "RPM"]


class ModelService:
    def __init__(self, model_dir: str = "./models", dataset_dir: str = "./data/raw"):
        self.model_dir = Path(model_dir)
        self.dataset_dir = Path(dataset_dir)
        self.model: Optional[RandomForestClassifier] = None
        self.model_version: str = "0.1.0-baseline"
        self.is_trained: bool = False
        self.metrics: Optional[Dict[str, Any]] = None
        self._lock = asyncio.Lock()

    def is_loaded(self) -> bool:
        return self.model is not None

    async def initialize(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
        model_path = self.model_dir / "baseline_rf.pkl"
        metrics_path = self.model_dir / "metrics.json"

        if model_path.exists():
            try:
                self.model = joblib.load(model_path)
                self.is_trained = True
                if metrics_path.exists():
                    with open(metrics_path) as f:
                        self.metrics = json.load(f)
                logger.info("Loaded existing model from %s", model_path)
                return
            except Exception as exc:
                logger.warning("Failed to load model: %s; will retrain", exc)

        await self._train_baseline()
    async def _train_baseline(self):
        """Train a RandomForest baseline from Car Hacking CSVs."""
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
            logger.warning("No dataset files found; creating untrained placeholder model")
            self.model = RandomForestClassifier(n_estimators=10, random_state=42)
            X_dummy = np.zeros((1, len(FEATURE_COLUMNS)))
            y_dummy = np.array(["Normal"])
            self.model.fit(X_dummy, y_dummy)
            self.is_trained = True
            self.metrics = {
                "accuracy": 0.0,
                "precision_macro": 0.0,
                "recall_macro": 0.0,
                "f1_macro": 0.0,
                "per_class": {},
                "confusion_matrix": [[0]],
                "classes": CLASS_LABELS,
                "training_samples": 0,
                "test_samples": 0,
                "note": "No dataset found - placeholder model",
            }
            return

        data = pd.concat(frames, ignore_index=True)
        logger.info("Total dataset: %d rows", len(data))

        X = self._engineer_features(data)
        y = data["label"].values

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
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

        joblib.dump(model, model_path)
        with open(metrics_path, "w") as f:
            json.dump(metrics, f, indent=2)

        logger.info(
            "Baseline trained: accuracy=%.4f, f1_macro=%.4f",
            metrics["accuracy"], metrics["f1_macro"],
        )

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

    def _engineer_features(self, df: pd.DataFrame) -> np.ndarray:
        features = []
        df = df.sort_values("timestamp").reset_index(drop=True)
        id_counts = df["arbitration_id"].value_counts().to_dict()
        prev_timestamp = None
        for _, row in df.iterrows():
            ts = row["timestamp"]
            delta_ms = 0.0 if prev_timestamp is None else (ts - prev_timestamp) * 1000.0
            prev_timestamp = ts
            dlc = int(row["dlc"])
            data_bytes = row["data_bytes"] if isinstance(row["data_bytes"], list) else []
            if isinstance(data_bytes, str):
                try:
                    data_bytes = [int(b, 16) for b in data_bytes.split()]
                except Exception:
                    data_bytes = []
            if data_bytes:
                byte_counts = np.bincount(data_bytes, minlength=256)
                probs = byte_counts / len(data_bytes)
                probs = probs[probs > 0]
                byte_entropy = float(-np.sum(probs * np.log2(probs)))
                data_byte_mean = float(np.mean(data_bytes))
                data_byte_std = float(np.std(data_bytes))
                data_byte_min = float(np.min(data_bytes))
                data_byte_max = float(np.max(data_bytes))
            else:
                byte_entropy = 0.0
                data_byte_mean = 0.0
                data_byte_std = 0.0
                data_byte_min = 0.0
                data_byte_max = 0.0
            can_id_freq = id_counts.get(row["arbitration_id"], 1)
            is_multi_byte = 1 if dlc > 1 else 0
            features.append([
                delta_ms, float(dlc), byte_entropy, float(can_id_freq),
                data_byte_mean, data_byte_std, data_byte_min, data_byte_max,
                float(is_multi_byte),
            ])
        return np.array(features, dtype=np.float32)

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

    def extract_features(self, frame_dict: Dict[str, Any]) -> np.ndarray:
        dlc = frame_dict.get("dlc", 0)
        data_bytes = frame_dict.get("data_bytes", [])
        if isinstance(data_bytes, str):
            try:
                data_bytes = [int(b, 16) for b in data_bytes.split()]
            except Exception:
                data_bytes = []
        if data_bytes:
            byte_counts = np.bincount(data_bytes, minlength=256)
            probs = byte_counts / len(data_bytes)
            probs = probs[probs > 0]
            byte_entropy = float(-np.sum(probs * np.log2(probs)))
            data_byte_mean = float(np.mean(data_bytes))
            data_byte_std = float(np.std(data_bytes))
            data_byte_min = float(np.min(data_bytes))
            data_byte_max = float(np.max(data_bytes))
        else:
            byte_entropy = 0.0
            data_byte_mean = 0.0
            data_byte_std = 0.0
            data_byte_min = 0.0
            data_byte_max = 0.0

        return np.array([[
            0.0, float(dlc), byte_entropy, 1.0,
            data_byte_mean, data_byte_std, data_byte_min, data_byte_max,
            1.0 if dlc > 1 else 0.0,
        ]], dtype=np.float32)

    async def predict(self, frame_dict: Dict[str, Any]) -> Tuple[str, float]:
        async with self._lock:
            if not self.is_trained or self.model is None:
                raise RuntimeError("Model not trained or loaded")
            X = self.extract_features(frame_dict)
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            confidence = float(np.max(probabilities))
            return str(prediction), confidence

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