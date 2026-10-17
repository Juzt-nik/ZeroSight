#!/usr/bin/env python3
"""Generate ZeroSight_ML_Pipeline.ipynb"""
import json

nb = {
    "cells": [],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3 (ipykernel)",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.11.0"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 5
}

def md_cell(source):
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": source if isinstance(source, list) else [source]
    }

def code_cell(source):
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": source if isinstance(source, list) else [source]
    }

# === Cell 1: Title / Overview ===
nb["cells"].append(md_cell("""
# ZeroSight ML Pipeline — Connected Vehicle CAN-bus Attack Detection

**IBM Z Datathon 2026 — AI Secured: Innovation Without Exposure**

This notebook implements the complete ML pipeline for the ZeroSight privacy-native vSOC:

- HCRL Car-Hacking dataset loading and validation (P1-05)
- Window-level (~100ms) CAN feature engineering shared by training and inference (P0-05)
- Time-based (contiguous segment) train/test split (P1-04)
- XGBoost supervised classifier on known attack classes (P1-03)
- Isolation Forest unsupervised anomaly detector on normal windows (P1-03)
- Ensemble logic combining both models with `unknown_anomaly` behavior
- Comprehensive evaluation: per-attack precision/recall/F1, FPR/hour, detection latency, inference latency, leave-one-attack-out, evasion degradation (P1-04)
- Model persistence with full metadata for reproducibility
- `predict_window()` inference function matching the FastAPI backend (P0-05 parity)

## Instance Constraints (RHEL 9.8, AI_LAB)

- 3 vCPUs, 8192MB RAM, 50GB disk — CPU-only training
- Windowed processing to respect memory limits
- Models saved to `./models/` for FastAPI backend consumption
"""))

# === Cell 2: Environment & Imports ===
nb["cells"].append(code_cell("""
# Section 1: Environment Setup & Imports

import os
import sys
import json
import uuid
import warnings
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib

# CPU thread limits for RHEL 9.8 instance (3 vCPUs, 8GB RAM)
os.environ["OMP_NUM_THREADS"] = "3"
os.environ["OPENBLAS_NUM_THREADS"] = "3"
os.environ["MKL_NUM_THREADS"] = "3"

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# Add project root to path for imports
PROJECT_ROOT = Path.cwd()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Configuration
DATASET_DIR = Path(os.getenv("DATASET_DIR", "./data/raw"))
MODEL_DIR = Path(os.getenv("MODEL_DIR", "./models"))
WINDOW_MS = float(os.getenv("WINDOW_MS", "100.0"))
USE_ENSEMBLE = os.getenv("USE_ENSEMBLE", "true").lower() in ("1", "true", "yes")
IF_CONTAMINATION = float(os.getenv("IF_CONTAMINATION", "0.1"))
RANDOM_SEED = int(os.getenv("RANDOM_SEED", "42"))

MODEL_DIR.mkdir(parents=True, exist_ok=True)
DATASET_DIR.mkdir(parents=True, exist_ok=True)

print(f"Project root: {PROJECT_ROOT}")
print(f"Dataset dir: {DATASET_DIR}")
print(f"Model dir: {MODEL_DIR}")
print(f"Window size: {WINDOW_MS} ms")
print(f"Use ensemble: {USE_ENSEMBLE}")
print(f"Python version: {sys.version}")
print(f"NumPy version: {np.__version__}")
print(f"Pandas version: {pd.__version__}")

try:
    import xgboost as xgb
    print(f"XGBoost version: {xgb.__version__}")
    XGB_AVAILABLE = True
except ImportError:
    print("XGBoost not available — falling back to RandomForest")
    XGB_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report
    )
    print("scikit-learn available")
    SKLEARN_AVAILABLE = True
except ImportError:
    print("scikit-learn not available")
    SKLEARN_AVAILABLE = False
"""))

with open(os.path.abspath(__file__), "w") as f:
    json.dump(nb, f, indent=2)

print("Part 1 written")