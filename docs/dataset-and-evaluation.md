# Dataset and Model Evaluation

## Dataset

The model pipeline uses the HCRL Car Hacking Dataset:

| File | Assigned class |
|---|---|
| `DoS_dataset.csv` | DoS |
| `Fuzzy_dataset.csv` | Fuzzy |
| `gear_dataset.csv` | Gear |
| `RPM_dataset.csv` | RPM |
| `normal_run_data.txt` | Normal |

Place the five files in `data/raw/`. Run `python scripts/validate_dataset.py
data/raw` to check for missing files, malformed frames, and unexpected labels.

## Features and split

Training and serving use the same versioned `WindowFeatureExtractor` from
`detection/features.py` (`1.0.0-window`) with 100 ms windows by default. It
builds message/unique-ID counts, lowest CAN ID, payload entropy, byte change
rate, DLC statistics, timestamp span, unseen-ID count, and per-ID count and
inter-arrival/frequency features.

The backend sorts windows by time and uses a contiguous 80/20 train/test split.
This is time-ordered evaluation; broader temporal leakage and cross-vehicle
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
