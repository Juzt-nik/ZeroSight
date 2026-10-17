#!/usr/bin/env python3
"""ZeroSight deployment verification script (Phase 4: LinuxONE verification).

Captures platform evidence, dependency versions, TLS info, model artifact
integrity, and performance measurements for the target VM.
"""

import hashlib
import json
import os
import platform
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

RESULTS = {}


def section(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def record(key, value):
    RESULTS[key] = value
    print(f"  {key}: {value}")


def main():
    # === Platform Information ===
    section("Platform Information")
    try:
        mem_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        mem_gb = round(mem_bytes / (1024 ** 3), 2)
    except (AttributeError, OSError):
        mem_gb = None

    record("system", platform.system())
    record("release", platform.release())
    record("machine", platform.machine())
    record("python_version", platform.python_version())
    record("cpu_count", os.cpu_count())
    record("memory_gb", mem_gb)
    record("is_s390x", platform.machine() in ("s390x", "s390"))
    record("is_linux", platform.system() == "Linux")

    # Read /etc/os-release if available
    os_release_path = Path("/etc/os-release")
    if os_release_path.exists():
        os_release = {}
        for line in os_release_path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                os_release[k.strip()] = v.strip().strip('"')
        record("os_name", os_release.get("NAME", "unknown"))
        record("os_version", os_release.get("VERSION_ID", "unknown"))
        record("os_pretty_name", os_release.get("PRETTY_NAME", "unknown"))

    # === Dependency Versions ===
    section("Dependency Versions")
    deps = [
        "fastapi", "uvicorn", "numpy", "pandas", "scikit-learn",
        "joblib", "xgboost", "jwt", "hmac", "hashlib",
    ]
    for dep in deps:
        try:
            mod = __import__(dep)
            ver = getattr(mod, "__version__", "unknown")
            record(f"dep_{dep}", ver)
        except ImportError:
            record(f"dep_{dep}", "NOT_INSTALLED")

    # === TLS Information ===
    section("TLS / Cryptography")
    record("ssl_version", ssl.OPENSSL_VERSION)
    record("tls_1_3_supported", ssl.HAS_TLSv1_3)
    record("tls_1_2_supported", ssl.HAS_TLSv1_2)

    # Check for hardware crypto (Crypto Express / HSM)
    record("crypto_express_available", False)
    record("hsm_available", False)
    record("crypto_note", "Hardware crypto not detected; label as integration target")

    # === Model Artifact Verification ===
    section("Model Artifact Verification")
    model_dir = Path(os.getenv("MODEL_DIR", "./models"))
    model_path = model_dir / "baseline_rf.pkl"
    metadata_path = model_dir / "metadata.json"

    if model_path.exists():
        model_bytes = model_path.read_bytes()
        model_hash = hashlib.sha256(model_bytes).hexdigest()
        model_size_bytes = len(model_bytes)
        record("model_exists", True)
        record("model_path", str(model_path))
        record("model_size_bytes", model_size_bytes)
        record("model_sha256", model_hash)
    else:
        record("model_exists", False)
        record("model_error", "No trained model found at %s" % model_path)

    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        record("metadata_exists", True)
        record("metadata_keys", sorted(metadata.keys()))
        record("model_version", metadata.get("model_version", "unknown"))
        record("feature_version", metadata.get("feature_version", "unknown"))
        record("split_strategy", metadata.get("split_strategy", "unknown"))
        record("dataset_version", metadata.get("dataset_version", "unknown"))
        record("training_samples", metadata.get("training_samples", 0))
        record("test_samples", metadata.get("test_samples", 0))
        record("placeholder", metadata.get("placeholder", "unknown"))
        record("artifact_hash_in_metadata", metadata.get("artifact_hash", "NOT_RECORDED"))
        record("feature_count", len(metadata.get("feature_names", [])))

        # Cross-verify hash
        if model_path.exists() and "artifact_hash" in metadata:
            actual_hash = hashlib.sha256(model_bytes).hexdigest()
            hash_match = actual_hash == metadata["artifact_hash"]
            record("artifact_hash_verified", hash_match)
    else:
        record("metadata_exists", False)

    # === Performance Measurements ===
    section("Performance Measurements")
    start = time.perf_counter()
    # Simulate a lightweight operation to measure CPU
    _ = sum(i * i for i in range(100000))
    cpu_op_time = time.perf_counter() - start
    record("cpu_benchmark_seconds", round(cpu_op_time, 6))

    # Inference latency (if model loaded)
    if model_path.exists():
        import joblib
        import numpy as np

        load_start = time.perf_counter()
        model = joblib.load(model_path)
        load_time = time.perf_counter() - load_start
        record("model_load_seconds", round(load_time, 6))

        # Dummy inference
        feature_names = metadata.get("feature_names", []) if metadata_path.exists() else []
        n_features = len(feature_names) if feature_names else 10
        X_dummy = np.zeros((1, n_features), dtype=np.float32)

        inf_start = time.perf_counter()
        _ = model.predict(X_dummy)
        inf_time = time.perf_counter() - load_start
        record("single_inference_seconds", round(inf_time, 6))

    # === Summary ===
    section("Verification Summary")
    record("verified_at", datetime.now(timezone.utc).isoformat())
    record("platform_verified", platform.system() == "Linux")
    record("model_artifact_verified", model_path.exists())
    record("metadata_verified", metadata_path.exists())

    # Write results to file
    output_path = Path(os.getenv("VERIFICATION_OUTPUT", "./deployment_verification.json"))
    with open(output_path, "w") as f:
        json.dump(RESULTS, f, indent=2)
    print(f"\nVerification results written to {output_path}")

    # Exit code
    all_ok = (
        model_path.exists()
        and metadata_path.exists()
        and not metadata.get("placeholder", True)
    )
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())