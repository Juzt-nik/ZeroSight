"""Replay-to-alert simulation (P1-01).

Deterministic replay of verified HCRL segments through the detection pipeline,
with synthetic vehicle/profile/GPS generation, ground-truth attack schedule,
and controlled start/reset/scene endpoints.
"""

import asyncio
import argparse
import json
import os
import random
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from backend.services.model_service import model_service
from backend.services.audit_service import audit_service
from backend.services.tokenization import generate_token
from backend.services.location import coarsen_location
from backend.services.preprocessing import parse_can_line

ATTACK_SCENES = {
    1: {
        "name": "Normal fleet / masking count",
        "description": "Baseline normal traffic with vehicle tokenization",
        "attack_segments": [],
    },
    2: {
        "name": "Known attack alert",
        "description": "DoS attack detected, masked alert generated",
        "attack_segments": ["DoS"],
    },
    3: {
        "name": "Denied unmask",
        "description": "Unmask request denied due to insufficient justification",
        "attack_segments": [],
    },
    4: {
        "name": "Dual-approved time-boxed unmask",
        "description": "Two security officers approve, identity temporarily released",
        "attack_segments": [],
    },
    5: {
        "name": "Audit tamper / verification failure",
        "description": "Chain tampering detected and reported",
        "attack_segments": [],
    },
    6: {
        "name": "Stolen credential / access anomaly",
        "description": "Access anomaly flags suspicious behavior",
        "attack_segments": [],
    },
    7: {
        "name": "Crypto scanner finding",
        "description": "RSA/ECC endpoint flagged for quantum migration",
        "attack_segments": [],
    },
}

SYNTHETIC_VINS = [f"VIN-SIM-{i:04d}" for i in range(1, 11)]
SYNTHETIC_GPS = [
    (40.7128, -74.0060),
    (34.0522, -118.2437),
    (51.5074, -0.1278),
]

class ReplaySimulator:
    def __init__(self, data_dir: Path, seed: int = 42):
        self.data_dir = data_dir
        self.seed = seed
        self.rng = random.Random(seed)
        self.vehicle_tokens: Dict[str, str] = {}
        self.vehicle_gps: Dict[str, tuple] = {}
        self.attack_schedule: List[Dict[str, Any]] = []
        self.is_running = False
        self.events_processed = 0
        self.alerts_generated = 0

    def assign_vehicle_token(self, vin: str) -> str:
        if vin not in self.vehicle_tokens:
            token, _, _ = generate_token(vin)
            self.vehicle_tokens[vin] = token
            self.vehicle_gps[vin] = self.rng.choice(SYNTHETIC_GPS)
        return self.vehicle_tokens[vin]

    def build_attack_schedule(
        self, attack_segments: List[str]
    ) -> List[Dict[str, Any]]:
        schedule = []
        label_map = {
            "DoS_dataset.csv": "DoS",
            "Fuzzy_dataset.csv": "Fuzzy",
            "gear_dataset.csv": "Gear",
            "RPM_dataset.csv": "RPM",
            "normal_run_data.txt": "Normal",
        }
        selected_labels = set(attack_segments) if attack_segments else {"Normal"}
        for fname, label in label_map.items():
            if label not in selected_labels:
                continue
            fpath = self.data_dir / fname
            if not fpath.exists():
                continue
            capture_frames = []
            with open(fpath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = parse_can_line(line)
                        capture_frames.append({
                            "timestamp": parsed["timestamp"],
                            "arbitration_id": parsed["arbitration_id"],
                            "dlc": parsed["dlc"],
                            "data_bytes": parsed["data_bytes"],
                            "ground_truth": parsed.get("label") if parsed.get("label") in ("Normal", "DoS", "Fuzzy", "Gear", "RPM") else label,
                        })
                    except ValueError:
                        continue
            capture_frames.sort(key=lambda x: x["timestamp"])
            if capture_frames:
                origin = capture_frames[0]["timestamp"]
                buckets: Dict[int, List[Dict[str, Any]]] = {}
                for frame in capture_frames:
                    bucket = int((frame["timestamp"] - origin) * 1000 // model_service.window_ms)
                    buckets.setdefault(bucket, []).append(frame)
                for bucket, window_frames in buckets.items():
                    labels = [frame["ground_truth"] for frame in window_frames]
                    schedule.append({
                        "timestamp": window_frames[0]["timestamp"],
                        "frames": window_frames,
                        "ground_truth": max(set(labels), key=labels.count),
                    })
        schedule.sort(key=lambda x: x["timestamp"])
        return schedule

    async def replay_segment(
        self, segment: Dict[str, Any], vehicle_vin: str
    ) -> Optional[Dict[str, Any]]:
        vehicle_token = self.assign_vehicle_token(vehicle_vin)

        lat, lon = self.vehicle_gps[vehicle_vin]
        location = coarsen_location(lat, lon, minimization_level="coarsen")

        frames = [{key: frame[key] for key in ("timestamp", "arbitration_id", "dlc", "data_bytes")}
                  for frame in segment["frames"]]
        prediction, confidence, features = await model_service.predict_window(frames)

        alert = None
        if prediction != "Normal":
            await audit_service.log_event(
                event_type="attack_alert",
                actor="system",
                outcome="success",
                details={
                    "prediction": prediction,
                    "confidence": confidence,
                    "arbitration_ids": sorted({frame["arbitration_id"] for frame in segment["frames"]}),
                    "frame_count": len(frames),
                    "vehicle_token": vehicle_token,
                    "ground_truth": segment["ground_truth"],
                    "features": features,
                    "location_grid": location.get("grid_cell"),
                },
            )
            alert = {
                "prediction": prediction,
                "confidence": confidence,
                "arbitration_ids": sorted({frame["arbitration_id"] for frame in segment["frames"]}),
                "frame_count": len(frames),
                "vehicle_token": vehicle_token,
                "ground_truth": segment["ground_truth"],
                "timestamp": segment["timestamp"],
            }

        self.events_processed += 1
        if alert:
            self.alerts_generated += 1

        return alert

    async def run_scene(
        self, scene_id: int, num_vehicles: int = 3
    ) -> Dict[str, Any]:
        scene = ATTACK_SCENES.get(scene_id)
        if not scene:
            raise ValueError(f"Unknown scene: {scene_id}")

        self.is_running = True
        self.events_processed = 0
        self.alerts_generated = 0

        self.attack_schedule = self.build_attack_schedule(
            scene["attack_segments"]
        )

        vehicles = SYNTHETIC_VINS[:num_vehicles]
        for vin in vehicles:
            self.assign_vehicle_token(vin)

        alerts = []
        for i, segment in enumerate(self.attack_schedule):
            vin = vehicles[i % len(vehicles)]
            alert = await self.replay_segment(segment, vin)
            if alert:
                alerts.append(alert)

        self.is_running = False

        return {
            "scene_id": scene_id,
            "scene_name": scene["name"],
            "description": scene["description"],
            "events_processed": self.events_processed,
            "alerts_generated": self.alerts_generated,
            "vehicles": vehicles,
            "vehicle_tokens": {
                vin: self.vehicle_tokens[vin] for vin in vehicles
            },
            "alerts": alerts[:10],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_scene_info(self) -> Dict[str, Any]:
        return {
            scene_id: {
                "name": info["name"],
                "description": info["description"],
            }
            for scene_id, info in ATTACK_SCENES.items()
        }


simulator: Optional[ReplaySimulator] = None


def get_simulator(data_dir: Optional[Path] = None) -> ReplaySimulator:
    global simulator
    if simulator is None:
        if data_dir is None:
            data_dir = Path(os.getenv("DATASET_DIR", "./data/raw"))
        simulator = ReplaySimulator(data_dir)
    return simulator
