# Dataset and Model Evaluation

## Dataset

The model pipeline uses the HCRL Car Hacking Dataset:

| File | Class assigned to HCRL `T` rows |
|---|---|
| `DoS_dataset.csv` | DoS |
| `Fuzzy_dataset.csv` | Fuzzy |
| `gear_dataset.csv` | Gear |
| `RPM_dataset.csv` | RPM |
| `normal_run_data.txt` | Normal |

Place the five files in `data/raw/`. Run `python scripts/validate_dataset.py
data/raw` to stream through each capture and report file sizes, row counts,
label counts, malformed rows, and CAN ID/payload parsing. CSV and normal text
capture formats are both supported; every payload must contain exactly DLC
hexadecimal bytes.

The validator explicitly maps HCRL `R` rows to `Normal` and `T` rows to the
attack class named by that attack capture. Explicit class labels are preserved;
missing or unsupported labels in attack captures fail validation. The default
quality gate rejects any individual capture with more than 0.1% malformed
nonempty rows. Set `DATASET_MAX_INVALID_ROW_RATE` or pass
`--max-invalid-rate` to use a different approved threshold. Training runs the
same validator first and refuses a dataset that fails the gate.

## Features and split

Training and serving use the same versioned `WindowFeatureExtractor` from
`detection/features.py` (`1.0.0-window`) with 100 ms windows by default. It
builds message/unique-ID counts, lowest CAN ID, payload entropy, byte change
rate, DLC statistics, timestamp span, unseen-ID count, and per-ID count and
inter-arrival/frequency features.

Training forms 100 ms buckets relative to each capture's first timestamp, so
frames from different captures can never share a window. Each capture is split
chronologically into its own 80/20 train/test windows. The reference CAN-ID
vocabulary is derived from training frames only, so test-only IDs are treated
as unseen. This is
time-ordered evaluation; broader temporal leakage and cross-vehicle
generalization have not been established.

## Model and metrics

The backend trains `RandomForestClassifier` and can optionally train an
`IsolationForest` on normal windows when `USE_ENSEMBLE=true`. XGBoost
availability is recorded as environment metadata, but the backend baseline
remains RandomForest.

Evaluation includes accuracy, macro precision/recall/F1, per-class
precision/recall/F1/support, and a confusion matrix. The authenticated load
runner separately reports observed throughput and latency; with labeled JSONL
input it also computes per-class results and false-positive rate on Normal
examples. Client round-trip and server `predict_window` duration are distinct
measurements.

## Reproduction

```powershell
python scripts/validate_dataset.py .\data\raw
python detection/train.py .\models .\data\raw
python detection/evaluate.py
```

The generated model artifact is intended for this repository's FastAPI model
service. Model artifacts are research-dataset based and have not been validated
on live vehicles or production CAN networks.
