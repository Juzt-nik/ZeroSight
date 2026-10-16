"""Preprocessing utilities for CAN bus frames.

Shared between detection service and detection CLI scripts.
"""

import numpy as np
from typing import Dict, Any, List


def parse_can_line(line: str) -> Dict[str, Any]:
    """Parse a single line from Car Hacking CSV format.

    Format: timestamp, arbitration_id, dlc, data_byte_1..N, label
    """
    line = line.strip()
    if not line:
        raise ValueError("Empty line")

    parts = line.split(",")
    if len(parts) < 4:
        raise ValueError(f"Too few fields: {len(parts)}")

    timestamp = float(parts[0])
    arbitration_id = parts[1]
    dlc = int(parts[2])

    # Data bytes: parts[3:-1] if last field is a label, else parts[3:]
    data_bytes: List[int] = []
    label = None

    if len(parts) >= 5:
        # Last part might be a label
        last = parts[-1]
        if last in ("R", "T", "A", "G", "F", "D", "Normal", "DoS", "Fuzzy", "Gear", "RPM"):
            label = last
            byte_parts = parts[3:-1]
        else:
            byte_parts = parts[3:]

        for b in byte_parts:
            b = b.strip()
            if b:
                try:
                    data_bytes.append(int(b, 16) if all(c in "0123456789abcdefABCDEF" for c in b) else int(b))
                except ValueError:
                    data_bytes.append(0)

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