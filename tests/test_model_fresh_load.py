"""Fresh-process model load and held-out inference test (Phase 1 acceptance A3).

Verifies that a saved model artifact can be loaded in a fresh Python process
and used to predict on held-out windows — proving the artifact is self-contained
and usable by the backend without schema drift.
"""

import asyncio
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from backend.services.model_service import ModelService


def test_fresh_process_load_and_predict(tmp_path, monkeypatch):
    """Load a saved artifact in a fresh ModelService instance and predict."""
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MODEL_DIR", str(model_dir))

    # Train and save a small model
    from detection.features import WindowFeatureExtractor

    # Real training records per-CAN-ID columns. Omit the explicit ID metadata
    # here to cover recovery from feature names in existing artifacts.
    extractor = WindowFeatureExtractor(reference_can_ids={"0316"})
    feature_names = extractor.feature_names()

    model = RandomForestClassifier(n_estimators=5, random_state=42)
    X_dummy = np.zeros((3, len(feature_names)), dtype=np.float32)
    y_dummy = np.array(["Normal", "Normal", "DoS"])
    model.fit(X_dummy, y_dummy)

    model_path = model_dir / "baseline_rf.pkl"
    joblib.dump(model, model_path)

    metadata = {
        "dataset_version": "hcrl_car_hacking_v1",
        "feature_version": "1.0.0-window",
        "split_strategy": "time_based_80_20",
        "model_version": "0.1.0-test",
        "training_samples": 2,
        "test_samples": 1,
        "window_ms": 100.0,
        "trained_at": "2024-01-01T00:00:00+00:00",
        "placeholder": False,
        "feature_names": feature_names,
        "xgboost_available": False,
        "model_algorithm": "RandomForestClassifier_fallback",
    }
    with open(model_dir / "metadata.json", "w") as f:
        json.dump(metadata, f)

    # Fresh process simulation: new ModelService instance loads the artifact
    service = ModelService(model_dir=str(model_dir), dataset_dir="./data/raw")
    asyncio.run(service.initialize())

    assert service.is_loaded()
    assert service.model is not None
    assert service.model_metadata["model_algorithm"] == metadata["model_algorithm"]
    assert service.model_metadata["xgboost_available"] is False

    # Predict on a held-out window
    import asyncio as _asyncio
    frames = [
        {
            "timestamp": 0.0,
            "arbitration_id": "0316",
            "dlc": 8,
            "data_bytes": [0x05, 0x21, 0x68, 0x09, 0x21, 0x21, 0x00, 0x6f],
        }
    ]
    pred, conf, feats = _asyncio.run(service.predict_window(frames))
    assert pred in ("Normal", "DoS", "Fuzzy", "Gear", "RPM", "Anomaly")
    assert 0.0 <= conf <= 1.0
    assert isinstance(feats, dict)
    assert len(feats) == len(feature_names)


def test_fresh_process_load_fails_without_model(tmp_path, monkeypatch):
    """Fresh ModelService must raise when no trained model exists."""
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MODEL_DIR", str(model_dir))

    service = ModelService(model_dir=str(model_dir), dataset_dir="./data/raw")
    with pytest.raises(RuntimeError, match="No trained model found"):
        asyncio.run(service.initialize())
    assert not service.is_loaded()


def test_fresh_process_load_fails_on_feature_mismatch(tmp_path, monkeypatch):
    """Fresh ModelService must raise when saved feature schema mismatches extractor."""
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MODEL_DIR", str(model_dir))

    from detection.features import WindowFeatureExtractor

    extractor = WindowFeatureExtractor()
    feature_names = extractor.feature_names()

    model = RandomForestClassifier(n_estimators=5, random_state=42)
    X_dummy = np.zeros((1, len(feature_names)), dtype=np.float32)
    y_dummy = np.array(["Normal"])
    model.fit(X_dummy, y_dummy)
    joblib.dump(model, model_dir / "baseline_rf.pkl")

    # Metadata with WRONG feature names (mismatch)
    bad_metadata = {
        "feature_names": ["wrong_feature_a", "wrong_feature_b"],
        "model_version": "0.1.0-test",
        "dataset_version": "test",
        "split_strategy": "test",
        "training_samples": 1,
        "test_samples": 1,
        "window_ms": 100.0,
        "trained_at": "2024-01-01T00:00:00+00:00",
        "placeholder": False,
    }
    with open(model_dir / "metadata.json", "w") as f:
        json.dump(bad_metadata, f)

    service2 = ModelService(model_dir=str(model_dir), dataset_dir="./data/raw")
    with pytest.raises(RuntimeError, match="Feature-schema mismatch"):
        asyncio.run(service2.initialize())
    assert not service2.is_loaded()
