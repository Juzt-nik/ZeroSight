"""Crypto scanner producing scoped CBOM output (P2-02).

Scans the demo's declared configuration/certificate inventory and emits a
machine-readable CycloneDX-compatible CBOM, identifying supported algorithm
and key metadata and flagging RSA/ECC for migration review.

Usage:
    python scripts/crypto_scanner.py [--config config.yaml] [--output cbom.json]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

# Algorithms considered quantum-safe or hybrid PQ
PQ_ALGORITHMS = {"ML-KEM", "ML-DSA", "SLH-DSA", "FIPS 203", "FIPS 204", "FIPS 205"}

# Algorithms flagged for migration review
LEGACY_ALGORITHMS = {"RSA", "ECC", "ECDSA", "ECDH", "DSA"}


def scan_config(config_path: Path) -> List[Dict[str, Any]]:
    """Scan a configuration file for crypto algorithm declarations."""
    findings = []
    if not config_path.exists():
        return findings

    try:
        content = config_path.read_text()
    except Exception:
        return findings

    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        upper = line.upper()
        for algo in LEGACY_ALGORITHMS:
            if algo in upper:
                findings.append({
                    "component": config_path.name,
                    "line": i,
                    "algorithm": algo,
                    "risk": "legacy",
                    "recommendation": f"Migrate {algo} to post-quantum alternative",
                })
        for algo in PQ_ALGORITHMS:
            if algo in upper:
                findings.append({
                    "component": config_path.name,
                    "line": i,
                    "algorithm": algo,
                    "risk": "pq_ready",
                    "recommendation": "Post-quantum algorithm in use",
                })
    return findings


def generate_cbom(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate a CycloneDX-compatible CBOM from scan findings."""
    components = []
    for i, finding in enumerate(findings):
        component = {
            "type": "library",
            "name": finding["component"],
            "version": "1.0.0",
            "properties": [
                {"name": "alg:algorithm", "value": finding["algorithm"]},
                {"name": "alg:risk", "value": finding["risk"]},
                {"name": "alg:line", "value": str(finding["line"])},
                {"name": "alg:recommendation", "value": finding["recommendation"]},
            ],
        }
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{__import__('uuid').uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "name": "ZeroSight Crypto Scanner",
                    "version": "0.1.0",
                }
            ],
        },
        "components": components,
    }


def main():
    parser = argparse.ArgumentParser(description="ZeroSight Crypto Scanner")
    parser.add_argument(
        "--config", type=Path, default=Path(".env.example"),
        help="Configuration file to scan",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("./cbom.json"),
        help="Output CBOM file path",
    )
    args = parser.parse_args()

    findings = scan_config(args.config)
    cbom = generate_cbom(findings)

    args.output.write_text(json.dumps(cbom, indent=2))
    print(json.dumps(cbom, indent=2))

    # Flag legacy algorithms for migration review
    legacy = [f for f in findings if f["risk"] == "legacy"]
    if legacy:
        print(
            f"\nWARNING: {len(legacy)} legacy algorithm(s) flagged for migration review",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print("\nNo legacy algorithms found.", file=sys.stderr)


if __name__ == "__main__":
    main()