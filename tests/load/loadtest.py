"""Authenticated load and labeled end-to-end evaluation for POST /detect/window."""

import argparse
import asyncio
import json
import math
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]


def read_cases(path: Path | None, count: int) -> list[dict[str, Any]]:
    if path:
        cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not cases:
            raise ValueError(f"No cases found in {path}")
        return cases
    now = datetime.now(timezone.utc).timestamp()
    # Unlabeled repeatable probe. Never treat a synthetic label as ground truth.
    return [{"frames": [{"timestamp": now + i * 0.1 + j * 0.001, "arbitration_id": "0316", "dlc": 8,
                         "data_bytes": [5, 33, 104, 9, 33, 33, 0, 111]} for j in range(8)]}
            for i in range(count)]


async def run(base_url: str, token: str, cases: list[dict[str, Any]], concurrency: int) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(concurrency)
    samples: list[dict[str, Any]] = []
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    started = time.perf_counter()

    async with httpx.AsyncClient(headers=headers, timeout=15.0) as client:
        async def send(case: dict[str, Any]):
            async with semaphore:
                payload = {key: value for key, value in case.items() if key in ("frames", "vehicle_token")}
                if "frames" not in payload and "frame" in case:
                    payload["frames"] = [case["frame"]]
                begin = time.perf_counter()
                try:
                    response = await client.post(f"{base_url.rstrip('/')}/detect/window", json=payload)
                    elapsed_ms = (time.perf_counter() - begin) * 1000
                    try:
                        body = response.json()
                    except ValueError:
                        body = {}
                    samples.append({"ok": response.status_code == 200, "status": response.status_code,
                                    "latency_ms": elapsed_ms, "label": case.get("label"),
                                    "prediction": body.get("prediction"),
                                    "inference_latency_ms": body.get("inference_latency_ms")})
                except httpx.HTTPError as exc:
                    samples.append({"ok": False, "status": "network_error", "latency_ms": (time.perf_counter() - begin) * 1000,
                                    "label": case.get("label"), "error": str(exc)})
        await asyncio.gather(*(send(case) for case in cases))
    duration = time.perf_counter() - started
    succeeded = [sample for sample in samples if sample["ok"]]
    latencies = [sample["latency_ms"] for sample in samples]
    per_attack: dict[str, Any] = {}
    labeled = [sample for sample in succeeded if sample["label"] is not None and sample["prediction"] is not None]
    for label in sorted({sample["label"] for sample in labeled}):
        group = [sample for sample in labeled if sample["label"] == label]
        per_attack[label] = {
            "samples": len(group), "detected_as_attack": sum(sample["prediction"] != "Normal" for sample in group),
            "correct_predictions": sum(sample["prediction"] == label for sample in group),
            "accuracy": sum(sample["prediction"] == label for sample in group) / len(group),
            "latency_ms": {"p50": round(percentile([s["latency_ms"] for s in group], .50), 2),
                           "p95": round(percentile([s["latency_ms"] for s in group], .95), 2)},
            "inference_latency_ms": {
                "p50": round(percentile([s["inference_latency_ms"] for s in group if s.get("inference_latency_ms") is not None], .50), 2),
                "p95": round(percentile([s["inference_latency_ms"] for s in group if s.get("inference_latency_ms") is not None], .95), 2),
            } if any(s.get("inference_latency_ms") is not None for s in group) else None,
        }
    normal = [sample for sample in labeled if sample["label"] == "Normal"]
    false_positives = sum(sample["prediction"] != "Normal" for sample in normal)
    return {
        "endpoint": "POST /detect/window", "total_requests": len(samples), "successes": len(succeeded),
        "errors": len(samples) - len(succeeded), "error_rate": (len(samples) - len(succeeded)) / len(samples),
        "throughput_rps": round(len(samples) / duration, 2) if duration else 0,
        "latency_ms": {"p50": round(percentile(latencies, .50), 2), "p95": round(percentile(latencies, .95), 2),
                       "p99": round(percentile(latencies, .99), 2), "min": round(min(latencies), 2), "max": round(max(latencies), 2)},
        "detection_latency_ms": {"p50": round(percentile([s["latency_ms"] for s in succeeded], .50), 2),
                                 "p95": round(percentile([s["latency_ms"] for s in succeeded], .95), 2)} if succeeded else None,
        "inference_latency_ms": {
            "p50": round(percentile([s["inference_latency_ms"] for s in succeeded if s.get("inference_latency_ms") is not None], .50), 2),
            "p95": round(percentile([s["inference_latency_ms"] for s in succeeded if s.get("inference_latency_ms") is not None], .95), 2),
        } if any(s.get("inference_latency_ms") is not None for s in succeeded) else None,
        "labeled_samples": len(labeled), "per_attack": per_attack,
        "false_positive_rate_on_normal": false_positives / len(normal) if normal else None,
        "normal_samples": len(normal), "status_codes": dict(Counter(str(s["status"]) for s in samples)),
        "duration_seconds": round(duration, 3),
        "latency_note": "Client-observed HTTP round trip; includes network and server overhead, not isolated model inference.",
        "metrics_note": "Per-attack/FPR metrics are omitted unless input cases include ground-truth label values.",
    }


def main():
    parser = argparse.ArgumentParser(description="Authenticated vSOC window inference load and labeled end-to-end run")
    parser.add_argument("--url", default=os.getenv("BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--token", default=os.getenv("VSOC_API_TOKEN"), help="Bearer token (or set VSOC_API_TOKEN)")
    parser.add_argument("--frames", type=int, default=1000, help="Unlabeled probe count when --input is omitted")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--input", type=Path, help="JSONL cases: each line {frames:[...], label:'Normal'|'DoS'|...}")
    parser.add_argument("--output", type=Path, default=Path("load_test_results.json"))
    args = parser.parse_args()
    if not args.token:
        parser.error("provide --token or set VSOC_API_TOKEN")
    if args.frames < 1 or args.concurrency < 1:
        parser.error("--frames and --concurrency must be positive")
    cases = read_cases(args.input, args.frames)
    summary = asyncio.run(run(args.url, args.token, cases, args.concurrency))
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
