"""Generate the backend-aligned ZeroSight ML pipeline notebook."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "ZeroSight_ML_Pipeline.ipynb"


def markdown(source: str) -> dict:
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": source.splitlines(keepends=True),
    }


def code(source: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": source.splitlines(keepends=True),
    }


cells = [
    markdown("""# ZeroSight ML Pipeline — Backend-Aligned Runbook

This notebook uses the repository's actual dataset validator, feature extractor,
and `ModelService`. It therefore trains the same RandomForest artifact that
FastAPI loads instead of maintaining a second implementation of preprocessing
and prediction.

## Phase coverage checked against this repository

| Phase | Current implementation | Notebook relationship |
|---|---|---|
| 0 | Shared versioned CAN window features and preprocessing are in `detection/features.py` and `backend/services/preprocessing.py`. | This notebook imports the shared implementation and checks its schema version. |
| 1 | Dataset validation, contiguous time split, RandomForest training, metrics, metadata, and fresh-load checks are in the scripts/backend/tests. | The train/evaluate cells call `ModelService`, producing `baseline_rf.pkl`, `metrics.json`, and `metadata.json`. |
| 2 | Token vault, RBAC, dual approval, and re-masking are backend privacy/access capabilities. | Backend/API scope; not duplicated in an ML notebook. See `tests/test_privacy.py` and `tests/test_access_control.py`. |
| 3 | Detection provenance, audit-driven anomaly monitoring, startup replay, and self-only manual event attribution are backend capabilities. | Backend/API scope; not duplicated here. See the Phase 3 section in `docs/path-to-production.md`. |

The notebook demonstrates the ML path only. It does not claim to execute or
validate the API, privacy, access-control, audit, or anomaly test suites.
"""),
    code("""# 1. Environment and repository paths
import os
import sys
import json
import time
import asyncio
from pathlib import Path

PROJECT_ROOT = Path.cwd().resolve()
if not (PROJECT_ROOT / "backend" / "services" / "model_service.py").exists():
    raise RuntimeError("Open this notebook with the repository root as the working directory.")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DATASET_DIR = Path(os.getenv("DATASET_DIR", str(PROJECT_ROOT / "data" / "raw")))
MODEL_DIR = Path(os.getenv("MODEL_DIR", str(PROJECT_ROOT / "models")))
MODEL_DIR.mkdir(parents=True, exist_ok=True)

print(f"Repository: {PROJECT_ROOT}")
print(f"Dataset:    {DATASET_DIR}")
print(f"Artifacts:  {MODEL_DIR}")
"""),
    markdown("""## 2. Validate the HCRL dataset

The backend trainer expects `DoS_dataset.csv`, `Fuzzy_dataset.csv`,
`gear_dataset.csv`, `RPM_dataset.csv`, and `normal_run_data.txt` in
`data/raw/` (or `DATASET_DIR`). Dataset validation may take several minutes
because these source files are large.
"""),
    code("""from scripts.validate_dataset import validate_dataset

validation = validate_dataset(DATASET_DIR)
print(json.dumps(validation, indent=2))
if not validation["valid"]:
    raise RuntimeError("Dataset validation failed; correct missing files or labels before training.")
"""),
    markdown("""## 3. Train with the backend implementation

`ModelService._train_baseline()` uses the shared `WindowFeatureExtractor`,
contiguous 80/20 time split, RandomForest classifier, optional Isolation Forest,
and the artifact/metrics/metadata contract used by the API. It writes the same
filenames expected by backend startup. Training can be memory- and CPU-intensive.
"""),
    code("""from backend.services.model_service import ModelService
from detection.features import FEATURE_VERSION, WindowFeatureExtractor

trainer = ModelService(model_dir=str(MODEL_DIR), dataset_dir=str(DATASET_DIR))
await trainer._train_baseline()

expected = ["baseline_rf.pkl", "metrics.json", "metadata.json"]
missing = [name for name in expected if not (MODEL_DIR / name).exists()]
if missing:
    raise RuntimeError(f"Training did not create expected backend artifacts: {missing}")
print("Created backend artifacts:", ", ".join(expected))
"""),
    markdown("""## 4. Confirm feature schema and model provenance

The fresh service load repeats backend artifact and feature-name checks. This
guards against schema drift between notebook-generated models and API inference.
"""),
    code("""service = ModelService(model_dir=str(MODEL_DIR), dataset_dir=str(DATASET_DIR))
await service.initialize()

metadata = service.model_metadata
extractor = WindowFeatureExtractor(window_ms=service.window_ms)
assert metadata["feature_version"] == FEATURE_VERSION
assert metadata["feature_names"] == extractor.feature_names()
assert metadata.get("placeholder") is False

print(json.dumps(metadata, indent=2))
print(f"Feature schema: {FEATURE_VERSION} ({len(metadata['feature_names'])} columns)")
"""),
    markdown("""## 5. Evaluation metrics

These metrics come from the backend's held-out time segment. The load-test
runner separately measures deployed API throughput, request latency, and
ground-truth per-attack/FPR results when given labeled cases.
"""),
    code("""metrics = service.get_metrics()
if not metrics:
    raise RuntimeError("The model has no stored evaluation metrics.")
print(json.dumps(metrics, indent=2))
"""),
    markdown("""## 6. Fresh-load inference and server call timing

This exercises the exact prediction path used by FastAPI. The elapsed time is
the server-side `predict_window` call duration, including any wait for its model
lock; API round-trip timing and throughput are measured by `tests/load/loadtest.py`.
"""),
    code("""sample_frames = [{
    "timestamp": 1760000000.0,
    "arbitration_id": "0316",
    "dlc": 8,
    "data_bytes": [5, 33, 104, 9, 33, 33, 0, 111],
}]
started = time.perf_counter()
prediction, confidence, features = await service.predict_window(sample_frames)
inference_latency_ms = (time.perf_counter() - started) * 1000

print(json.dumps({
    "prediction": prediction,
    "confidence": confidence,
    "inference_latency_ms": round(inference_latency_ms, 4),
    "feature_count": len(features),
    "model_version": service.model_version,
    "feature_version": metadata["feature_version"],
}, indent=2))
"""),
    markdown("""## 7. Phase 2 and Phase 3 backend checks (scope boundary)

The notebook does not reproduce security-sensitive backend behavior. Phase 2
token-vault access, two-person unmask approvals, and re-masking are implemented
in the privacy/access services and covered by backend tests. Phase 3 adds
model/feature provenance to attack audit records, audit-event ingestion into the
anomaly detector, startup replay of persisted records, and authenticated-user
attribution checks for manual anomaly events. Use the backend test suite and API
demo for those flows; this notebook only produces and exercises an ML model.

No performance result is considered a deployment/load-test result until the
authenticated `tests/load/loadtest.py` command is run against the target API.
"""),
]

notebook = {
    "cells": cells,
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3 (ipykernel)",
            "language": "python",
            "name": "python3",
        },
        "language_info": {"name": "python", "version": "3.11.0"},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

OUTPUT.write_text(json.dumps(notebook, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"Generated {OUTPUT} ({len(cells)} cells)")
