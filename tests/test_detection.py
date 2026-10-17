"""Tests for detection module."""

import asyncio
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from backend.services.model_service import ModelService
from backend.services.preprocessing import parse_can_line


def test_parse_can_line():
    line = "1478198376.389427,0316,8,05,21,68,09,21,21,00,6f,R"
    parsed = parse_can_line(line)
    assert parsed["timestamp"] == 1478198376.389427
    assert parsed["arbitration_id"] == "0316"
    assert parsed["dlc"] == 8
    assert parsed["label"] == "R"


def test_parse_can_line_malformed():
    with pytest.raises(ValueError):
        parse_can_line("too,few,fields")


def test_parse_normal_capture_format_and_reject_bad_payload():
    parsed = parse_can_line(
        "Timestamp: 1479121434.850202 ID: 0350 000 DLC: 8 05 28 84 66 6d 00 00 a2"
    )
    assert parsed["arbitration_id"] == "0350"
    assert parsed["data_bytes"] == [5, 40, 132, 102, 109, 0, 0, 162]
    with pytest.raises(ValueError, match="payload byte"):
        parse_can_line("1.0,0316,2,05,zz,R")
    with pytest.raises(ValueError, match="payload byte"):
        parse_can_line("1.0,0316,2,05,R")


def test_windows_never_combine_separate_captures():
    service = ModelService()
    service.feature_extractor = __import__(
        "detection.features", fromlist=["WindowFeatureExtractor"]
    ).WindowFeatureExtractor(window_ms=100.0)
    df = __import__("pandas").DataFrame([
        {"capture_id": "capture-a", "timestamp": 1.0, "arbitration_id": "0316", "dlc": 1,
         "data_bytes": [1], "label": "Normal"},
        {"capture_id": "capture-b", "timestamp": 1.0, "arbitration_id": "0260", "dlc": 1,
         "data_bytes": [2], "label": "DoS"},
    ])
    X, y, _ = service._engineer_features(df)
    assert X.shape[0] == 2
    assert set(y) == {"Normal", "DoS"}


def test_model_initializes(tmp_path, monkeypatch):
    """ModelService.initialize() loads a saved artifact or fails safely."""
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MODEL_DIR", str(model_dir))

    # No trained model → initialize() must raise RuntimeError (no dummy fallback)
    service = ModelService(model_dir=str(model_dir), dataset_dir="./data/raw")
    with pytest.raises(RuntimeError, match="No trained model found"):
        asyncio.run(service.initialize())
    assert not service.is_loaded()

    # With a saved model → initialize() loads successfully
    from detection.features import WindowFeatureExtractor

    _extractor = WindowFeatureExtractor()
    feature_names = _extractor.feature_names()

    model = RandomForestClassifier(n_estimators=5, random_state=42)
    X_dummy = np.zeros((1, len(feature_names)), dtype=np.float32)
    y_dummy = np.array(["Normal"])
    model.fit(X_dummy, y_dummy)
    model_path = model_dir / "baseline_rf.pkl"
    joblib.dump(model, model_path)

    # Save metadata with feature names matching the extractor
    metadata = {
        "feature_names": feature_names,
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
        json.dump(metadata, f)

    service2 = ModelService(model_dir=str(model_dir), dataset_dir="./data/raw")
    asyncio.run(service2.initialize())
    assert service2.is_loaded()
    assert service2.model is not None
