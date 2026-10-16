# Models Directory

Trained model artifacts are stored here:
- `baseline_rf.pkl` — RandomForest baseline model
- `metrics.json` — Evaluation metrics

Train the baseline model:
```
python detection/train.py ./models ./data/raw
```

## Model Limitations
- Baseline RandomForest, not XGBoost (chosen for s390x compatibility).
- Trained on HCRL Car Hacking dataset only.
- No real-world vehicle validation claimed.
- SHAP explainability available optionally (memory permitting).