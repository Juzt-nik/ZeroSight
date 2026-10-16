"""Feature engineering module for CAN bus frames (reusable)."""

import numpy as np
from typing import Dict, Any, List

FEATURE_COLUMNS = [
    "timestamp_delta_ms",
    "dlc",
    "byte_entropy",
    "can_id_freq",
    "data_byte_mean",
    "data_byte_std",
    "data_byte_min",
    "data_byte_max",
    "is_multi_byte",
]


def extract_features(frame_dict: Dict[str, Any]) -> List[float]:
    """Extract feature vector from a single CAN frame dict."""
    dlc = frame_dict.get("dlc", 0)
    data_bytes = frame_dict.get("data_bytes", [])
    if isinstance(data_bytes, str):
        data_bytes = [int(b, 16) for b in data_bytes.split()]

    if data_bytes:
        byte_counts = np.bincount(data_bytes, minlength=256)
        probs = byte_counts / len(data_bytes)
        probs = probs[probs > 0]
        byte_entropy = float(-np.sum(probs * np.log2(probs)))
        data_byte_mean = float(np.mean(data_bytes))
        data_byte_std = float(np.std(data_bytes))
        data_byte_min = float(np.min(data_bytes))
        data_byte_max = float(np.max(data_bytes))
    else:
        byte_entropy = 0.0
        data_byte_mean = 0.0
        data_byte_std = 0.0
        data_byte_min = 0.0
        data_byte_max = 0.0

    return [
        0.0, float(dlc), byte_entropy, 1.0,
        data_byte_mean, data_byte_std, data_byte_min, data_byte_max,
        1.0 if dlc > 1 else 0.0,
    ]