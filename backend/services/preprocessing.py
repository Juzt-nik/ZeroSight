"""Preprocessing utilities for CAN bus frames.

Shared between detection service and detection CLI scripts.
"""

import numpy as np
import re
from typing import Dict, Any, List

HCRL_LABELS = {"R", "T", "A", "G", "F", "D", "Normal", "DoS", "Fuzzy", "Gear", "RPM"}
ATTACK_CLASSES = {"DoS", "Fuzzy", "Gear", "RPM"}


def normalize_hcrl_label(raw_label: str | None, capture_label: str) -> str:
    """Normalize HCRL labels while preserving row-level normal/attack markers.

    HCRL's R marker means a normal row. T means an attack row and is mapped to
    the named attack type of that capture. Explicit class labels are preserved.
    The unlabeled normal text capture is the only source allowed to omit a label.
    """
    if raw_label == "R":
        return "Normal"
    if raw_label == "T":
        if capture_label not in ATTACK_CLASSES:
            raise ValueError("HCRL attack marker T requires an attack capture class")
        return capture_label
    if raw_label in {"Normal", "DoS", "Fuzzy", "Gear", "RPM"}:
        return raw_label
    if raw_label is None and capture_label == "Normal":
        return "Normal"
    raise ValueError(f"Missing or unsupported HCRL row label: {raw_label!r}")


def parse_can_line(line: str) -> Dict[str, Any]:
    """Parse a single line from Car Hacking CSV format.

    Format: timestamp, arbitration_id, dlc, data_byte_1..N, label
    """
    line = line.strip()
    if not line:
        raise ValueError("Empty line")

    # HCRL attack captures are CSV; the normal capture uses a labeled text
    # format: Timestamp: ... ID: ... 000 DLC: ... <hex bytes>.
    text_match = re.match(
        r"^Timestamp:\s*([0-9.eE+-]+)\s+ID:\s*([0-9a-fA-F]+)\s+\S+\s+DLC:\s*(\d+)\s*(.*?)\s*$",
        line,
    )
    if text_match:
        timestamp, arbitration_id, dlc, payload = text_match.groups()
        parts = [timestamp, arbitration_id, dlc, *payload.split()]
    else:
        parts = [part.strip() for part in line.split(",")]
    if len(parts) < 3:
        raise ValueError(f"Too few fields: {len(parts)}")

    timestamp = float(parts[0])
    if not np.isfinite(timestamp) or timestamp < 0:
        raise ValueError("Timestamp must be finite and non-negative")
    arbitration_id = parts[1].strip().lower()
    try:
        can_id = int(arbitration_id, 16)
    except ValueError as exc:
        raise ValueError(f"Invalid CAN ID: {arbitration_id}") from exc
    if can_id < 0 or can_id > 0x1FFFFFFF:
        raise ValueError(f"CAN ID out of range: {arbitration_id}")
    dlc = int(parts[2])
    if not 0 <= dlc <= 8:
        raise ValueError(f"DLC must be between 0 and 8: {dlc}")

    # Use DLC and field count to distinguish an optional label from a final
    # payload byte whose one-character hex value happens to be e.g. "A".
    data_bytes: List[int] = []
    label = None
    if len(parts) == 3 + dlc:
        byte_parts = parts[3:]
    elif len(parts) == 4 + dlc:
        label = parts[-1]
        if label not in HCRL_LABELS:
            raise ValueError(f"Unknown label: {label}")
        byte_parts = parts[3:-1]
    else:
        raise ValueError(f"DLC is {dlc}, but row has {len(parts) - 3} payload/label fields")

    for b in byte_parts:
        b = b.strip()
        if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,2}", b):
            raise ValueError(f"Invalid CAN payload byte: {b!r}")
        data_bytes.append(int(b, 16))

    return {
        "timestamp": timestamp,
        "arbitration_id": arbitration_id,
        "dlc": dlc,
        "data_bytes": data_bytes,
        "label": label,
    }


def frame_to_dict(frame) -> Dict[str, Any]:
    """Convert a pydantic CANFrame to a plain dict for feature extraction."""
    return {
        "timestamp": frame.timestamp,
        "arbitration_id": frame.arbitration_id,
        "dlc": frame.dlc,
        "data_bytes": frame.data_bytes,
        "label": frame.label,
    }
