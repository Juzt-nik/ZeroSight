"""CLI preprocessing for CAN bus datasets."""

import sys
from pathlib import Path
from backend.services.preprocessing import parse_can_line


def preprocess_file(input_path: Path, output_path: Path):
    """Parse a raw CAN CSV and write cleaned output."""
    with open(input_path, "r") as fin, open(output_path, "w") as fout:
        fout.write("timestamp,arbitration_id,dlc,data_bytes,label\n")
        for line in fin:
            try:
                parsed = parse_can_line(line)
                data_hex = ",".join(f"{b:02x}" for b in parsed["data_bytes"])
                fout.write(f"{parsed['timestamp']},{parsed['arbitration_id']},{parsed['dlc']},{data_hex},{parsed['label']}\n")
            except Exception:
                continue
    print(f"Preprocessed {input_path} -> {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python preprocess.py <input> <output>")
        sys.exit(1)
    preprocess_file(Path(sys.argv[1]), Path(sys.argv[2]))