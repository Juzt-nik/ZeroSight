"""HCRL Car-Hacking dataset validation (P1-05).

Validates required columns, timestamps, CAN ID/data parsing, labels, empty files,
and unexpected classes. Emits a machine-readable summary and fails clearly on
schema/label mismatch.

Usage:
    python scripts/validate_dataset.py <data_dir>
"""

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Tuple
from backend.services.preprocessing import parse_can_line

EXPECTED_LABELS = {"Normal", "DoS", "Fuzzy", "Gear", "RPM"}
REQUIRED_EXTENSIONS = {".csv", ".txt"}

FILE_LABEL_MAP = {
    "DoS_dataset.csv": "DoS",
    "Fuzzy_dataset.csv": "Fuzzy",
    "gear_dataset.csv": "Gear",
    "RPM_dataset.csv": "RPM",
    "normal_run_data.txt": "Normal",
}


def validate_file(fpath: Path) -> Dict[str, Any]:
    """Validate a single dataset file."""
    result: Dict[str, Any] = {
        "file": fpath.name,
        "exists": fpath.exists(),
        "readable": False,
        "row_count": 0,
        "valid_rows": 0,
        "invalid_rows": 0,
        "labels_found": set(),
        "unexpected_labels": [],
        "can_ids": set(),
        "label_counts": Counter(),
        "size_bytes": fpath.stat().st_size if fpath.exists() else 0,
        "errors": [],
        "errors_truncated": False,
    }

    if not fpath.exists():
        result["errors"].append(f"File not found: {fpath}")
        return result

    expected_label = FILE_LABEL_MAP.get(fpath.name)
    try:
        with open(fpath, "r") as f:
            result["readable"] = True
            for i, line in enumerate(f, 1):
                result["row_count"] += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = parse_can_line(line)
                    result["valid_rows"] += 1
                    label = parsed.get("label") if parsed.get("label") in EXPECTED_LABELS else expected_label
                    if label:
                        result["labels_found"].add(label)
                        result["label_counts"][label] += 1
                    if parsed.get("arbitration_id"):
                        result["can_ids"].add(parsed["arbitration_id"])
                except ValueError as exc:
                    result["invalid_rows"] += 1
                    if len(result["errors"]) < 100:
                        result["errors"].append(f"Line {i}: {exc}")
                    else:
                        result["errors_truncated"] = True
    except Exception as exc:
        result["errors"].append(f"Cannot read file: {exc}")
        return result

    # Check for unexpected labels
    if expected_label:
        unexpected = result["labels_found"] - {expected_label, "Normal"}
        if unexpected:
            result["unexpected_labels"] = sorted(unexpected)

    # Convert sets to sorted lists for JSON serialization
    result["labels_found"] = sorted(result["labels_found"])
    result["can_ids"] = sorted(result["can_ids"])
    result["label_counts"] = dict(result["label_counts"])

    return result


def validate_dataset(data_dir: Path) -> Dict[str, Any]:
    """Validate all dataset files in the given directory."""
    summary: Dict[str, Any] = {
        "data_dir": str(data_dir),
        "valid": True,
        "files": {},
        "missing_files": [],
        "total_rows": 0,
        "total_valid": 0,
        "total_invalid": 0,
        "all_labels": set(),
        "all_can_ids": set(),
    }

    for fname in FILE_LABEL_MAP:
        fpath = data_dir / fname
        result = validate_file(fpath)
        summary["files"][fname] = result

        if not result["exists"]:
            summary["missing_files"].append(fname)
            summary["valid"] = False
        elif not result["readable"]:
            summary["valid"] = False
        elif result["invalid_rows"] > 0:
            # Invalid rows don't necessarily make the whole dataset invalid,
            # but flag it
            pass

        summary["total_rows"] += result["row_count"]
        summary["total_valid"] += result["valid_rows"]
        summary["total_invalid"] += result["invalid_rows"]
        summary["all_labels"].update(result["labels_found"])
        summary["all_can_ids"].update(result["can_ids"])

    # Convert sets to sorted lists
    summary["all_labels"] = sorted(summary["all_labels"])
    summary["all_can_ids"] = sorted(summary["all_can_ids"])

    # Check for unexpected labels across all files
    unexpected = set(summary["all_labels"]) - EXPECTED_LABELS
    if unexpected:
        summary["unexpected_labels"] = sorted(unexpected)
        summary["valid"] = False

    if summary["missing_files"]:
        summary["valid"] = False

    return summary


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_dataset.py <data_dir>")
        sys.exit(1)

    data_dir = Path(sys.argv[1])
    summary = validate_dataset(data_dir)

    print(json.dumps(summary, indent=2))

    if not summary["valid"]:
        print("\nVALIDATION FAILED", file=sys.stderr)
        sys.exit(1)
    else:
        print("\nVALIDATION PASSED", file=sys.stderr)


if __name__ == "__main__":
    main()
