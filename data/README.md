# Data Directory

## Raw Datasets
Place the Car Hacking dataset CSVs here:
- `DoS_dataset.csv`
- `Fuzzy_dataset.csv`
- `gear_dataset.csv`
- `RPM_dataset.csv`
- `normal_run_data.txt`

These files are large (190-240 MB each) and are **not** included in the repository.
Copy them from your source location:
```
cp /path/to/DoS_dataset.csv data/raw/
```

## Synthetic Data
The `data/synthetic/` directory contains generated demo events with no real PII.

## Dataset Limitations
- The HCRL Car Hacking dataset is from a research vehicle, not production vehicles.
- Labels are attack-type specific (DoS, Fuzzy, Gear, RPM) and "R" for regular/normal.
- No real driver identities or GPS coordinates are present.
- Results from this dataset should not be claimed as real-world vehicle validation.