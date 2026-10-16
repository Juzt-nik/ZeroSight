"""CLI prediction script for single CAN frames."""

import asyncio
import sys
import json
from backend.services.model_service import ModelService


async def main():
    service = ModelService()
    await service.initialize()
    if len(sys.argv) > 1:
        frame = json.loads(sys.argv[1])
    else:
        frame = {"dlc": 8, "data_bytes": [0x05, 0x21, 0x68, 0x09, 0x21, 0x21, 0x00, 0x6f]}
    pred, conf = await service.predict(frame)
    print(f"Prediction: {pred}, Confidence: {conf:.4f}")


if __name__ == "__main__":
    asyncio.run(main())