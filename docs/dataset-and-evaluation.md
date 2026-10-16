# Dataset and Model Evaluation

## Dataset
HCRL Car Hacking Dataset (CAN bus intrusion detection):

| File | Attack Type |
|------|-------------|
| `DoS_dataset.csv` | Denial of Service |
| `Fuzzy_dataset.csv` | Fuzzy attack |
| `gear_dataset.csv` | Gear spoofing |
| `RPM_dataset.csv` | RPM spoofing |
| `normal_run_data.txt` | Normal traffic |

## Features
- `timestamp_delta_ms` — time since previous frame
- `dlc` — data length code
- `byte_entropy` — Shannon entropy of data bytes
- `can_id_freq` — frequency of arbitration ID
- `data_byte_mean/std/min/max` — byte statistics
- `is_multi_byte` — whether DLC > 1

## Model
Baseline: `RandomForestClassifier` (scikit-learn)
- 100 estimators, max_depth=16, class_weight="balanced"
- Train/test split: 80/20 stratified

## Metrics
Evaluated with: accuracy, precision (macro), recall (macro), F1 (macro),
per-class precision/recall/F1/support, confusion matrix.

## Limitations
- **No real-world vehicle validation.** Results are research-dataset only.
- **No data leakage claim verified.** Train/test split is stratified but temporal leakage not analyzed.
- **Dataset is from 2015 research vehicle.** May not generalize to modern CAN buses.
- **No XGBoost** due to s390x wheel availability; RandomForest used instead.

## Reproducing Evaluation
```
python detection/train.py ./models ./data/raw
python detection/evaluate.py
```