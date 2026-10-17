"""Streaming HCRL dataset validation with an explicit malformed-row limit.

Usage: python scripts/validate_dataset.py <data_dir> [--max-invalid-rate 0.001]
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from backend.services.preprocessing import normalize_hcrl_label, parse_can_line

EXPECTED_LABELS = {"Normal", "DoS", "Fuzzy", "Gear", "RPM"}
FILE_LABEL_MAP = {
    "DoS_dataset.csv": "DoS",
    "Fuzzy_dataset.csv": "Fuzzy",
    "gear_dataset.csv": "Gear",
    "RPM_dataset.csv": "RPM",
    "normal_run_data.txt": "Normal",
}
DEFAULT_MAX_INVALID_ROW_RATE = float(os.getenv("DATASET_MAX_INVALID_ROW_RATE", "0.001"))


def validate_file(
    fpath: Path, max_invalid_rate: float = DEFAULT_MAX_INVALID_ROW_RATE
) -> dict[str, Any]:
    expected_label = FILE_LABEL_MAP.get(fpath.name, "")
    result: dict[str, Any] = {
        "file": fpath.name,
        "exists": fpath.exists(),
        "readable": False,
        "size_bytes": fpath.stat().st_size if fpath.exists() else 0,
        "row_count": 0,
        "nonempty_rows": 0,
        "valid_rows": 0,
        "invalid_rows": 0,
        "invalid_row_rate": 0.0,
        "quality_passed": False,
        "labels_found": set(),
        "label_counts": Counter(),
        "can_ids": set(),
        "errors": [],
        "errors_truncated": False,
    }
    if not fpath.exists():
        result["errors"].append(f"File not found: {fpath}")
        return result

    try:
        with fpath.open("r", encoding="utf-8", errors="replace") as source:
            result["readable"] = True
            for line_number, raw_line in enumerate(source, 1):
                result["row_count"] += 1
                line = raw_line.strip()
                if not line:
                    continue
                result["nonempty_rows"] += 1
                try:
                    parsed = parse_can_line(line)
                    label = normalize_hcrl_label(parsed.get("label"), expected_label)
                    result["valid_rows"] += 1
                    result["labels_found"].add(label)
                    result["label_counts"][label] += 1
                    result["can_ids"].add(parsed["arbitration_id"])
                except (ValueError, UnicodeError) as exc:
                    result["invalid_rows"] += 1
                    if len(result["errors"]) < 100:
                        result["errors"].append(f"Line {line_number}: {exc}")
                    else:
                        result["errors_truncated"] = True
    except Exception as exc:
        result["errors"].append(f"Cannot read file: {exc}")
        return result

    denominator = result["nonempty_rows"]
    result["invalid_row_rate"] = result["invalid_rows"] / denominator if denominator else 1.0
    result["quality_passed"] = (
        denominator > 0 and result["invalid_row_rate"] <= max_invalid_rate
    )
    result["labels_found"] = sorted(result["labels_found"])
    result["label_counts"] = dict(result["label_counts"])
    result["can_ids"] = sorted(result["can_ids"])
    return result


def validate_dataset(
    data_dir: Path, max_invalid_rate: float = DEFAULT_MAX_INVALID_ROW_RATE
) -> dict[str, Any]:
    """Validate required capture files, labels, parsing, and malformed-row rate."""
    if not 0 <= max_invalid_rate < 1:
        raise ValueError("max_invalid_rate must be in [0, 1)")

    summary: dict[str, Any] = {
        "data_dir": str(data_dir),
        "valid": True,
        "files": {},
        "missing_files": [],
        "total_rows": 0,
        "total_valid": 0,
        "total_invalid": 0,
        "invalid_row_rate": 0.0,
        "max_invalid_row_rate": max_invalid_rate,
        "quality_failures": [],
        "all_labels": set(),
        "all_can_ids": set(),
    }
    for filename in FILE_LABEL_MAP:
        result = validate_file(data_dir / filename, max_invalid_rate)
        summary["files"][filename] = result
        if not result["exists"]:
            summary["missing_files"].append(filename)
            summary["valid"] = False
        elif not result["readable"]:
            summary["valid"] = False
        elif not result["quality_passed"]:
            summary["quality_failures"].append({
                "file": filename,
                "invalid_rows": result["invalid_rows"],
                "nonempty_rows": result["nonempty_rows"],
                "invalid_row_rate": result["invalid_row_rate"],
            })
            summary["valid"] = False

        summary["total_rows"] += result["row_count"]
        summary["total_valid"] += result["valid_rows"]
        summary["total_invalid"] += result["invalid_rows"]
        summary["all_labels"].update(result["labels_found"])
        summary["all_can_ids"].update(result["can_ids"])

    nonempty_rows = sum(file["nonempty_rows"] for file in summary["files"].values())
    summary["invalid_row_rate"] = summary["total_invalid"] / max(nonempty_rows, 1)
    summary["all_labels"] = sorted(summary["all_labels"])
    summary["all_can_ids"] = sorted(summary["all_can_ids"])
    if set(summary["all_labels"]) - EXPECTED_LABELS:
        summary["valid"] = False
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream-validate HCRL CAN captures")
    parser.add_argument("data_dir", type=Path)
    parser.add_argument(
        "--max-invalid-rate", type=float, default=DEFAULT_MAX_INVALID_ROW_RATE,
        help="Maximum malformed nonempty-row ratio allowed per capture (default: 0.001)",
    )
    args = parser.parse_args()
    summary = validate_dataset(args.data_dir, args.max_invalid_rate)
    print(json.dumps(summary, indent=2))
    if not summary["valid"]:
        print("\nVALIDATION FAILED", file=sys.stderr)
        raise SystemExit(1)
    print("\nVALIDATION PASSED", file=sys.stderr)


if __name__ == "__main__":
    main()
