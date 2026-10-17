"""Feature engineering module for CAN bus frames (reusable).

P0-05: Implements a shared, versioned window-level CAN feature extractor used
by training, evaluation, and online inference. Features are aggregated over
configurable time windows (default ~100 ms) per the blueprint §5.1-§5.3.
"""

import numpy as np
from typing import Dict, Any, List, Optional, Set

FEATURE_VERSION = "1.0.0-window"
DEFAULT_WINDOW_MS = 100.0

BASE_FEATURE_COLUMNS = [
    "window_start_ms",
    "window_end_ms",
    "message_count",
    "unique_id_count",
    "lowest_can_id",
    "payload_entropy",
    "byte_change_rate",
    "dlc_mean",
    "dlc_std",
    "timestamp_delta_ms",
]

PER_ID_PREFIX = "per_id_count_"
UNSEEN_ID_COUNT = "unseen_id_count"


def _can_id_to_int(can_id: str) -> int:
    return int(can_id, 16)


def _compute_byte_entropy(data_bytes: List[int]) -> float:
    if not data_bytes:
        return 0.0
    counts = np.bincount(data_bytes, minlength=256)
    probs = counts / len(data_bytes)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def _compute_byte_change_rate(prev_bytes, curr_bytes) -> float:
    if prev_bytes is None or len(prev_bytes) != len(curr_bytes):
        return 0.0
    diffs = sum(1 for a, b in zip(prev_bytes, curr_bytes) if a != b)
    return diffs / len(curr_bytes)


class WindowFeatureExtractor:
    """Extracts versioned window-level features from a sequence of CAN frames.

    Frames should be sorted by timestamp before being passed in. The extractor
    aggregates frames into fixed-duration windows and computes statistical
    features suitable for ML training and online inference.
    """

    def __init__(
        self,
        window_ms: float = DEFAULT_WINDOW_MS,
        reference_can_ids: Optional[Set[str]] = None,
        feature_version: str = FEATURE_VERSION,
    ):
        self.window_ms = window_ms
        self.reference_can_ids = set(reference_can_ids) if reference_can_ids else set()
        self.feature_version = feature_version

    def extract_window(
        self,
        frames: List[Dict[str, Any]],
        window_start_ms: float,
    ) -> Dict[str, Any]:
        """Extract features for a single window of frames."""
        window_end_ms = window_start_ms + self.window_ms

        if not frames:
            return self._empty_features(window_start_ms, window_end_ms)

        can_ids = [f.get("arbitration_id", "0") for f in frames]
        can_id_ints = [_can_id_to_int(cid) for cid in can_ids]
        dlcs = [f.get("dlc", 0) for f in frames]
        data_bytes_list = [f.get("data_bytes", []) for f in frames]
        timestamps = [f.get("timestamp", 0.0) for f in frames]

        message_count = len(frames)
        unique_ids = set(can_ids)
        unique_id_count = len(unique_ids)
        lowest_can_id = min(can_id_ints) if can_id_ints else 0

        all_bytes = [b for db in data_bytes_list for b in db]
        payload_entropy = _compute_byte_entropy(all_bytes)

        change_rates = []
        for i, db in enumerate(data_bytes_list):
            if i == 0:
                change_rates.append(0.0)
            else:
                change_rates.append(
                    _compute_byte_change_rate(data_bytes_list[i - 1], db)
                )
        byte_change_rate = float(np.mean(change_rates)) if change_rates else 0.0

        dlc_mean = float(np.mean(dlcs)) if dlcs else 0.0
        dlc_std = float(np.std(dlcs)) if dlcs else 0.0

        if len(timestamps) > 1:
            ts_ms = [t * 1000.0 if t < 1e12 else t for t in timestamps]
            timestamp_delta_ms = float(max(ts_ms) - min(ts_ms))
        else:
            timestamp_delta_ms = 0.0

        per_id_counts: Dict[str, int] = {}
        per_id_timestamps: Dict[str, List[float]] = {}
        for cid, ts in zip(can_ids, timestamps):
            ts_ms = ts * 1000.0 if ts < 1e12 else ts
            per_id_counts[cid] = per_id_counts.get(cid, 0) + 1
            per_id_timestamps.setdefault(cid, []).append(ts_ms)

        per_id_features: Dict[str, float] = {}
        for cid in sorted(unique_ids):
            key = f"{PER_ID_PREFIX}{cid}"
            per_id_features[key] = float(per_id_counts.get(cid, 0))

            ts_list = sorted(per_id_timestamps.get(cid, []))
            if len(ts_list) > 1:
                inter_arrivals = np.diff(ts_list)
                per_id_features[f"{cid}_inter_arrival_mean_ms"] = float(
                    np.mean(inter_arrivals)
                )
                per_id_features[f"{cid}_inter_arrival_std_ms"] = float(
                    np.std(inter_arrivals)
                )
            else:
                per_id_features[f"{cid}_inter_arrival_mean_ms"] = 0.0
                per_id_features[f"{cid}_inter_arrival_std_ms"] = 0.0

            if self.window_ms > 0:
                per_id_features[f"ID_FREQ_HZ_{cid}"] = (
                    per_id_counts.get(cid, 0) / (self.window_ms / 1000.0)
                )
            else:
                per_id_features[f"ID_FREQ_HZ_{cid}"] = 0.0

        unseen_id_count = sum(
            1 for cid in unique_ids if cid not in self.reference_can_ids
        )

        features: Dict[str, Any] = {
            "window_start_ms": window_start_ms,
            "window_end_ms": window_end_ms,
            "message_count": float(message_count),
            "unique_id_count": float(unique_id_count),
            "lowest_can_id": float(lowest_can_id),
            "payload_entropy": payload_entropy,
            "byte_change_rate": byte_change_rate,
            "dlc_mean": dlc_mean,
            "dlc_std": dlc_std,
            "timestamp_delta_ms": timestamp_delta_ms,
            UNSEEN_ID_COUNT: float(unseen_id_count),
        }
        features.update(per_id_features)
        return features

    def _empty_features(
        self, window_start_ms: float, window_end_ms: float
    ) -> Dict[str, Any]:
        return {
            "window_start_ms": window_start_ms,
            "window_end_ms": window_end_ms,
            "message_count": 0.0,
            "unique_id_count": 0.0,
            "lowest_can_id": 0.0,
            "payload_entropy": 0.0,
            "byte_change_rate": 0.0,
            "dlc_mean": 0.0,
            "dlc_std": 0.0,
            "timestamp_delta_ms": 0.0,
            UNSEEN_ID_COUNT: 0.0,
        }

    def feature_names(self, include_per_id: bool = True) -> List[str]:
        names = list(BASE_FEATURE_COLUMNS)
        names.append(UNSEEN_ID_COUNT)
        if include_per_id:
            for cid in sorted(self.reference_can_ids):
                names.append(f"{PER_ID_PREFIX}{cid}")
                names.append(f"{cid}_inter_arrival_mean_ms")
                names.append(f"{cid}_inter_arrival_std_ms")
                names.append(f"ID_FREQ_HZ_{cid}")
        return names

    def to_vector(
        self, features: Dict[str, Any], feature_names: Optional[List[str]] = None
    ) -> np.ndarray:
        if feature_names is None:
            feature_names = self.feature_names()
        vector = []
        for name in feature_names:
            vector.append(float(features.get(name, 0.0)))
        return np.array([vector], dtype=np.float32)


def extract_features(frame_dict: Dict[str, Any]) -> List[float]:
    """Legacy single-frame feature extraction (backward compatible).

    Deprecated: use WindowFeatureExtractor for window-level features. This
    function exists for backward compatibility with existing tests and the
    model service predict path.
    """
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