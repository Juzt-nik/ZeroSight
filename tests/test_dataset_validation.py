"""Dataset quality gate regressions."""

from scripts.validate_dataset import validate_dataset


def _csv_row(timestamp, label):
    return f"{timestamp},0316,2,05,0a,{label}\n"


def test_validator_reports_malformed_rows_and_rejects_threshold_excess(tmp_path):
    files = {
        "DoS_dataset.csv": _csv_row(1, "R") + _csv_row(2, "T") + "not,a,can,row\n",
        "Fuzzy_dataset.csv": _csv_row(1, "T"),
        "gear_dataset.csv": _csv_row(1, "T"),
        "RPM_dataset.csv": _csv_row(1, "T"),
        "normal_run_data.txt": "Timestamp: 1.0 ID: 0316 000 DLC: 2 05 0a\n",
    }
    for filename, contents in files.items():
        (tmp_path / filename).write_text(contents, encoding="utf-8")

    report = validate_dataset(tmp_path, max_invalid_rate=0.2)
    dos = report["files"]["DoS_dataset.csv"]
    assert dos["invalid_rows"] == 1
    assert dos["valid_rows"] == 2
    assert dos["label_counts"] == {"DoS": 1, "Normal": 1}
    assert dos["errors"]
    assert report["valid"] is False
    assert report["quality_failures"][0]["file"] == "DoS_dataset.csv"


def test_validator_accepts_rows_at_or_below_configured_threshold(tmp_path):
    files = {
        "DoS_dataset.csv": _csv_row(1, "R") + _csv_row(2, "T") + "malformed\n",
        "Fuzzy_dataset.csv": _csv_row(1, "T"),
        "gear_dataset.csv": _csv_row(1, "T"),
        "RPM_dataset.csv": _csv_row(1, "T"),
        "normal_run_data.txt": "Timestamp: 1.0 ID: 0316 000 DLC: 2 05 0a\n",
    }
    for filename, contents in files.items():
        (tmp_path / filename).write_text(contents, encoding="utf-8")

    report = validate_dataset(tmp_path, max_invalid_rate=0.34)
    assert report["valid"] is True
    assert report["files"]["DoS_dataset.csv"]["invalid_row_rate"] == 1 / 3
