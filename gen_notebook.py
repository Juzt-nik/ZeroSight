"""Generate a self-contained notebook for the ZeroSight ML pipeline."""

import base64
import io
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "ZeroSight_ML_Pipeline.ipynb"

# Bundle the exact training/inference modules into the notebook so hosted
# notebook runners do not need a repository checkout or network access.
BUNDLE_FILES = [
    "backend/services/model_service.py",
    "backend/services/preprocessing.py",
    "detection/features.py",
    "detection/train.py",
    "scripts/validate_dataset.py",
]
_bundle_buffer = io.BytesIO()
with zipfile.ZipFile(_bundle_buffer, "w", compression=zipfile.ZIP_DEFLATED) as _bundle:
    for _relative in BUNDLE_FILES:
        _bundle.write(ROOT / _relative, _relative)
    for _package in ("backend", "backend/services", "detection", "scripts"):
        _bundle.writestr(f"{_package}/__init__.py", "")
BUNDLE_B64 = base64.b64encode(_bundle_buffer.getvalue()).decode("ascii")


def markdown(source: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": source.splitlines(keepends=True)}


def code(source: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": source.splitlines(keepends=True),
    }


cells = [
    markdown("""# ZeroSight ML Pipeline - End-to-End Runbook

This standalone notebook embeds the parsing, validation, windowing, feature
extraction, and training modules it needs. It handles dataset validation,
isolated candidate training, artifact reload, held-out metrics, complete-window
inference, and a saved verification report without cloning the repository.

The reproducible training entry point is `detection/train.py`. Each input file
is a separate capture. HCRL `R` rows normalize to `Normal`; `T` rows normalize
to that attack capture's class; explicit supported class labels are preserved.
Each capture receives its own chronological 80/20 window split, and the
reference CAN-ID vocabulary comes from training frames only. The streaming
validator rejects any capture exceeding the default 0.1% malformed-row rate.
"""),
    code("""# 1. Extract the embedded project and locate the dataset
import os
import sys
import json
import time
import subprocess
import base64
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path

BUNDLE_B64 = "__EMBEDDED_PROJECT_BUNDLE__"
REQUIRED_DATA_FILES = {
    "DoS_dataset.csv", "Fuzzy_dataset.csv", "gear_dataset.csv",
    "RPM_dataset.csv", "normal_run_data.txt",
}

def is_project_root(path):
    return (path / "backend" / "services" / "model_service.py").is_file() and \
        (path / "detection" / "train.py").is_file()

cwd = Path.cwd().resolve()
PROJECT_ROOT = Path(os.getenv("PROJECT_ROOT", str(cwd / "ZeroSight"))).expanduser().resolve()
PROJECT_ROOT.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(io.BytesIO(base64.b64decode(BUNDLE_B64))) as embedded_project:
    embedded_project.extractall(PROJECT_ROOT)
if not is_project_root(PROJECT_ROOT):
    raise RuntimeError(f"Embedded project bundle is incomplete: {PROJECT_ROOT}")

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def has_all_dataset_files(path):
    return path.is_dir() and REQUIRED_DATA_FILES.issubset({item.name for item in path.iterdir()})

configured_dataset = os.getenv("DATASET_DIR")
if configured_dataset:
    DATASET_DIR = Path(configured_dataset).expanduser().resolve()
elif has_all_dataset_files(PROJECT_ROOT / "data" / "raw"):
    DATASET_DIR = PROJECT_ROOT / "data" / "raw"
else:
    search_roots = [Path("/kaggle/input"), Path("/content"), cwd]
    DATASET_DIR = None
    searched = set()
    for search_root in search_roots:
        if not search_root.exists():
            continue
        for candidate in search_root.rglob("DoS_dataset.csv"):
            parent = candidate.parent.resolve()
            if parent in searched:
                continue
            searched.add(parent)
            if has_all_dataset_files(parent):
                DATASET_DIR = parent
                break
        if DATASET_DIR:
            break
if not DATASET_DIR or not has_all_dataset_files(DATASET_DIR):
    raise FileNotFoundError(
        "Could not locate all five HCRL dataset files. Upload/mount them together "
        "in one folder, then set DATASET_DIR to that folder before running this cell. "
        f"Required files: {sorted(REQUIRED_DATA_FILES)}"
    )

run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
default_model_dir = PROJECT_ROOT / "models" / "candidates" / run_id
MODEL_DIR = Path(os.getenv("MODEL_DIR", str(default_model_dir)))
MODEL_DIR.mkdir(parents=True, exist_ok=True)
print(f"Embedded project: {PROJECT_ROOT}")
print(f"Dataset:    {DATASET_DIR}")
print(f"Candidate:  {MODEL_DIR}")
""".replace("__EMBEDDED_PROJECT_BUNDLE__", BUNDLE_B64)),
    markdown("""## 2. Stream-validate the dataset

The validator reads the five expected HCRL files line by line. Its report
includes byte sizes, physical/nonempty/valid/invalid row counts, normalized
label counts, CAN IDs, and representative parse errors. The default
per-capture malformed-row limit is 0.1%; override it only with an approved
quality threshold. Training runs this same gate before reading data.
"""),
    code("""from scripts.validate_dataset import validate_dataset, DEFAULT_MAX_INVALID_ROW_RATE

validation = validate_dataset(
    DATASET_DIR,
    max_invalid_rate=DEFAULT_MAX_INVALID_ROW_RATE,
)
print(json.dumps(validation, indent=2))
if not validation["valid"]:
    raise RuntimeError("Dataset validation failed. Do not train this candidate.")
validation_path = MODEL_DIR / "dataset_validation.json"
validation_path.write_text(json.dumps(validation, indent=2), encoding="utf-8")
print(f"Validation report: {validation_path}")
"""),
    markdown("""### Dataset quality and label distribution

The first panel compares valid and malformed rows by capture. The second
shows the row-level class distribution reported by the validator.
"""),
    code("""import matplotlib.pyplot as plt

capture_names = list(validation["files"])
valid_counts = [validation["files"][name]["valid_rows"] for name in capture_names]
invalid_counts = [validation["files"][name]["invalid_rows"] for name in capture_names]
label_counts = {}
for file_result in validation["files"].values():
    for label, count in file_result["label_counts"].items():
        label_counts[label] = label_counts.get(label, 0) + count

fig, axes = plt.subplots(1, 2, figsize=(14, 5))
positions = range(len(capture_names))
axes[0].bar(positions, valid_counts, label="Valid rows", color="#2a9d8f")
axes[0].bar(positions, invalid_counts, bottom=valid_counts, label="Malformed rows", color="#e76f51")
axes[0].set_xticks(list(positions), capture_names, rotation=35, ha="right")
axes[0].set_ylabel("Rows")
axes[0].set_title("Rows by capture")
axes[0].legend()
axes[1].bar(list(label_counts), list(label_counts.values()), color="#457b9d")
axes[1].set_ylabel("Rows")
axes[1].set_title("Normalized row labels")
axes[1].tick_params(axis="x", rotation=30)
fig.tight_layout()
plt.show()
"""),
    markdown("""## 3. Train an isolated candidate with the CLI

This cell invokes `detection/train.py` in a subprocess. The default candidate
directory has a unique UTC timestamp; set `MODEL_DIR` before opening the
notebook to choose a different isolated location. Run this after the validation
report is clean. The CLI refuses data that fails the quality gate:

```sh
python detection/train.py ./models/candidate ./data/raw
```

The CLI saves the model, metrics, feature schema, training-only reference IDs,
split provenance, and SHA-256 artifact hash for API startup verification.
"""),
    code("""if (MODEL_DIR / "baseline_rf.pkl").exists():
    raise RuntimeError(f"Candidate already has a model; choose a fresh MODEL_DIR: {MODEL_DIR}")

training_command = [
    sys.executable,
    "-m",
    "detection.train",
    str(MODEL_DIR),
    str(DATASET_DIR),
]
training_started = time.perf_counter()
training_result = subprocess.run(
    training_command, cwd=PROJECT_ROOT, text=True, capture_output=True
)
training_runtime_seconds = time.perf_counter() - training_started
if training_result.stdout:
    print(training_result.stdout)
if training_result.stderr:
    print(training_result.stderr)
if training_result.returncode:
    raise RuntimeError(f"Training CLI failed with exit code {training_result.returncode}")

expected_artifacts = ["baseline_rf.pkl", "metrics.json", "metadata.json"]
missing_artifacts = [name for name in expected_artifacts if not (MODEL_DIR / name).is_file()]
if missing_artifacts:
    raise RuntimeError(f"Training did not create expected artifacts: {missing_artifacts}")
print(f"Training runtime: {training_runtime_seconds:.2f} seconds")
"""),
    markdown("""## 4. Load the candidate and verify its schema

Point `MODEL_DIR` at the candidate directory. A new `ModelService` instance
performs the same artifact hash and feature-schema checks as API startup.
"""),
    code("""from backend.services.model_service import ModelService
from detection.features import FEATURE_VERSION, WindowFeatureExtractor

service = ModelService(model_dir=str(MODEL_DIR), dataset_dir=str(DATASET_DIR))
await service.initialize()

metadata = service.model_metadata
extractor = WindowFeatureExtractor(
    window_ms=service.window_ms,
    reference_can_ids=set(metadata["reference_can_ids"]),
)
metrics = service.get_metrics()
assert metadata["feature_version"] == FEATURE_VERSION
assert metadata["feature_names"] == extractor.feature_names()
assert metadata["split_strategy"] == "capture_aware_chronological_80_20"
assert metadata["training_samples"] == metrics["training_samples"]
assert metadata["test_samples"] == metrics["test_samples"]

print(json.dumps(metadata, indent=2))
print(f"Feature schema: {FEATURE_VERSION} ({len(metadata['feature_names'])} columns)")
"""),
    markdown("""## 5. Held-out evaluation metrics

These metrics are computed from the chronological test tail of each capture.
They are actual model results; API load and per-window ground-truth metrics
must be measured separately against the deployed service.
"""),
    code("""if not metrics:
    raise RuntimeError("The candidate has no stored evaluation metrics.")
print(json.dumps(metrics, indent=2))

# Plot observed held-out model results from the stored evaluation.
import numpy as np
import matplotlib.pyplot as plt

classes = metrics["classes"]
cm = np.asarray(metrics["confusion_matrix"])
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
image = axes[0].imshow(cm, cmap="Blues")
axes[0].set_xticks(range(len(classes)), classes, rotation=35, ha="right")
axes[0].set_yticks(range(len(classes)), classes)
axes[0].set_xlabel("Predicted label")
axes[0].set_ylabel("True label")
axes[0].set_title("Held-out confusion matrix")
for row in range(cm.shape[0]):
    for col in range(cm.shape[1]):
        axes[0].text(col, row, int(cm[row, col]), ha="center", va="center", color="black")
fig.colorbar(image, ax=axes[0], fraction=0.046, pad=0.04)

per_class = metrics["per_class"]
metric_names = ["precision", "recall", "f1"]
x = np.arange(len(classes))
width = 0.24
for index, metric_name in enumerate(metric_names):
    values = [per_class.get(label, {}).get(metric_name, 0.0) for label in classes]
    axes[1].bar(x + (index - 1) * width, values, width, label=metric_name.title())
axes[1].set_xticks(x, classes, rotation=35, ha="right")
axes[1].set_ylim(0, 1)
axes[1].set_ylabel("Score")
axes[1].set_title("Per-class held-out metrics")
axes[1].legend()
fig.tight_layout()
plt.show()

if hasattr(service.model, "feature_importances_"):
    importances = service.model.feature_importances_
    top_indices = np.argsort(importances)[-15:]
    feature_names = [metadata["feature_names"][index] for index in top_indices]
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(feature_names, importances[top_indices], color="#6a4c93")
    ax.set_xlabel("Random Forest importance")
    ax.set_title("Top 15 window features")
    fig.tight_layout()
    plt.show()
"""),
    markdown("""## 6. Verify reload and inference in a fresh process

This starts another Python interpreter and loads the persisted artifact from
disk. A successful training run alone does not establish that API startup can
restore the feature schema or perform inference.
"""),
    code("""fresh_process_code = r'''\
import asyncio, json, sys
from backend.services.model_service import ModelService

async def main():
    service = ModelService(model_dir=sys.argv[1], dataset_dir=sys.argv[2])
    await service.initialize()
    frames = [{
        "timestamp": 1760000000.0 + index * 0.001,
        "arbitration_id": "0316", "dlc": 8,
        "data_bytes": [5, 33, 104, 9, 33, 33, 0, 111],
    } for index in range(8)]
    prediction, confidence, features = await service.predict_window(frames)
    print(json.dumps({
        "prediction": prediction,
        "confidence": confidence,
        "feature_count": len(features),
        "model_version": service.model_version,
        "artifact_hash": service.model_metadata["artifact_hash"],
        "frame_count": len(frames),
    }))

asyncio.run(main())
'''
fresh_result = subprocess.run(
    [sys.executable, "-c", fresh_process_code, str(MODEL_DIR), str(DATASET_DIR)],
    cwd=PROJECT_ROOT,
    check=True,
    text=True,
    capture_output=True,
)
fresh_process_inference = json.loads(fresh_result.stdout.strip().splitlines()[-1])
print(json.dumps(fresh_process_inference, indent=2))
"""),
    markdown("""## 7. Predict from a complete CAN window

`POST /detect/window` passes all frames from one bounded window to a single
model inference call. This cell exercises the same `predict_window` method on
eight frames within 100 ms. The timer is model-call duration, not API round-trip
latency.
"""),
    code("""sample_frames = [{
    "timestamp": 1760000000.0 + index * 0.001,
    "arbitration_id": "0316",
    "dlc": 8,
    "data_bytes": [5, 33, 104, 9, 33, 33, 0, 111],
} for index in range(8)]

started = time.perf_counter()
prediction, confidence, features = await service.predict_window(sample_frames)
inference_latency_ms = (time.perf_counter() - started) * 1000
print(json.dumps({
    "prediction": prediction,
    "confidence": confidence,
    "inference_latency_ms": round(inference_latency_ms, 4),
    "frame_count": len(sample_frames),
    "feature_count": len(features),
    "model_version": service.model_version,
    "feature_version": metadata["feature_version"],
}, indent=2))

fig, axes = plt.subplots(1, 2, figsize=(10, 4))
axes[0].bar(["Prediction confidence"], [confidence], color="#2a9d8f")
axes[0].set_ylim(0, 1)
axes[0].set_ylabel("Confidence")
axes[0].set_title(f"Window prediction: {prediction}")
axes[1].bar(["Inference"], [inference_latency_ms], color="#e9c46a")
axes[1].set_ylabel("Milliseconds")
axes[1].set_title("Single-window model-call latency")
fig.tight_layout()
plt.show()

verification_report = {
    "created_at": datetime.now(timezone.utc).isoformat(),
    "dataset_validation": validation,
    "training_runtime_seconds": round(training_runtime_seconds, 4),
    "model_metadata": metadata,
    "metrics": metrics,
    "fresh_process_inference": fresh_process_inference,
    "notebook_inference": {
        "prediction": prediction,
        "confidence": confidence,
        "inference_latency_ms": round(inference_latency_ms, 4),
        "frame_count": len(sample_frames),
        "feature_count": len(features),
    },
}
report_path = MODEL_DIR / "notebook_verification_report.json"
report_path.write_text(json.dumps(verification_report, indent=2), encoding="utf-8")
print(f"Verification report saved: {report_path}")
"""),
    markdown("""## Scope

This notebook covers data quality, CLI training, model reload, evaluation,
inference, and an ML verification report. API authentication, privacy and
dual-approval flows, and deployment load testing remain separate service-level
checks. Use `tests/load/loadtest.py` against the target API for those checks.
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
