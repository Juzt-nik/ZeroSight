"""CLI evaluation script: print model metrics."""

import asyncio
import json
from backend.services.model_service import ModelService


async def main():
    service = ModelService()
    await service.initialize()
    metrics = service.get_metrics()
    if metrics:
        print(json.dumps(metrics, indent=2))
    else:
        print("No metrics available")


if __name__ == "__main__":
    asyncio.run(main())