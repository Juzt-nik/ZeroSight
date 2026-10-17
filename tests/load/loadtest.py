"""Load test for ZeroSight API endpoints (P2-03).

Measures throughput, latency percentiles, error rates, and end-to-end
probe-alert latency against integrated endpoints.

Usage:
    python tests/load/loadtest.py --url http://localhost:8000 --frames 1000
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

import httpx


class LoadTestResult:
    def __init__(self):
        self.latencies: List[float] = []
        self.errors: int = 0
        self.total_requests: int = 0
        self.alerts_detected: int = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    def add_request(self, latency_ms: float, success: bool, is_alert: bool = False):
        self.latencies.append(latency_ms)
        self.total_requests += 1
        if not success:
            self.errors += 1
        if is_alert:
            self.alerts_detected += 1

    def summary(self) -> Dict[str, Any]:
        if not self.latencies:
            return {"error": "No requests completed"}

        sorted_lat = sorted(self.latencies)
        n = len(sorted_lat)
        p50 = sorted_lat[int(n * 0.5)]
        p95 = sorted_lat[int(n * 0.95)]
        p99 = sorted_lat[int(n * 0.99)]

        duration = self.end_time - self.start_time
        throughput = self.total_requests / duration if duration > 0 else 0

        return {
            "total_requests": self.total_requests,
            "errors": self.errors,
            "error_rate": self.errors / self.total_requests if self.total_requests else 0,
            "alerts_detected": self.alerts_detected,
            "throughput_rps": round(throughput, 2),
            "latency_ms": {
                "p50": round(p50, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
                "min": round(min(sorted_lat), 2),
                "max": round(max(sorted_lat), 2),
            },
            "duration_seconds": round(duration, 2),
        }


async def run_load_test(
    base_url: str, num_frames: int, concurrency: int
) -> LoadTestResult:
    result = LoadTestResult()
    result.start_time = time.time()

    semaphore = asyncio.Semaphore(concurrency)

    async def send_frame(client: httpx.AsyncClient, frame_idx: int):
        async with semaphore:
            frame = {
                "timestamp": datetime.now(timezone.utc).timestamp(),
                "arbitration_id": "0316",
                "dlc": 8,
                "data_bytes": [0x05, 0x21, 0x68, 0x09, 0x21, 0x21, 0x00, 0x6f],
                "label": "DoS" if frame_idx % 100 == 0 else "Normal",
            }
            start = time.time()
            try:
                resp = await client.post(
                    f"{base_url}/detect/",
                    json={"frame": frame},
                    timeout=10.0,
                )
                latency_ms = (time.time() - start) * 1000
                is_alert = False
                if resp.status_code == 200:
                    data = resp.json()
                    is_alert = data.get("prediction", "Normal") != "Normal"
                result.add_request(latency_ms, resp.status_code == 200, is_alert)
            except Exception:
                latency_ms = (time.time() - start) * 1000
                result.add_request(latency_ms, False)

    async with httpx.AsyncClient() as client:
        tasks = [
            send_frame(client, i) for i in range(num_frames)
        ]
        await asyncio.gather(*tasks)

    result.end_time = time.time()
    return result


def main():
    parser = argparse.ArgumentParser(description="ZeroSight Load Test")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL")
    parser.add_argument("--frames", type=int, default=1000, help="Number of frames")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency level")
    parser.add_argument(
        "--output", type=Path, default=Path("./load_test_results.json"),
        help="Output results file",
    )
    args = parser.parse_args()

    print(f"Running load test: {args.frames} frames, {args.concurrency} concurrent")
    print(f"Target: {args.url}")

    result = asyncio.run(
        run_load_test(args.url, args.frames, args.concurrency)
    )
    summary = result.summary()

    print(json.dumps(summary, indent=2))

    args.output.write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()