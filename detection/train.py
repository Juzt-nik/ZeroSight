"""CLI training script for the baseline detector."""

import asyncio
import sys
from pathlib import Path
from backend.services.model_service import ModelService


async def main():
    model_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./models")
    dataset_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./data/raw")
    service = ModelService(model_dir=str(model_dir), dataset_dir=str(dataset_dir))
    await service.initialize()
    metrics = service.get_metrics()
    if metrics:
        print(f"Training complete. Accuracy: {metrics['accuracy']}, F1 macro: {metrics['f1_macro']}")
    else:
        print("Training complete. No metrics available.")


if __name__ == "__main__":
    asyncio.run(main())