"""CLI training script for the baseline detector.

Usage:
    python detection/train.py [model_dir] [dataset_dir]

Trains a RandomForest baseline from HCRL Car-Hacking CSVs and saves the
model artifact, metrics, and metadata to model_dir (default ./models).
"""

import asyncio
import sys
from pathlib import Path

from backend.services.model_service import ModelService


async def main():
    model_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./models")
    dataset_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./data/raw")
    service = ModelService(model_dir=str(model_dir), dataset_dir=str(dataset_dir))

    # Try to load an existing model; if none exists, train from scratch.
    try:
        await service.initialize()
        print(f"Model already loaded from {model_dir}. No retraining needed.")
    except RuntimeError as exc:
        if "No trained model found" in str(exc):
            logger = __import__("logging").getLogger("vsoc.train")
            logger.info("No trained model found — training from scratch.")
            await service._train_baseline()
            metrics = service.get_metrics()
            if metrics:
                print(
                    f"Training complete. Accuracy: {metrics['accuracy']:.4f}, "
                    f"F1 macro: {metrics['f1_macro']:.4f}, "
                    f"samples: train={metrics['training_samples']}, "
                    f"test={metrics['test_samples']}"
                )
            else:
                print("Training complete. No metrics available.")
        else:
            raise


if __name__ == "__main__":
    asyncio.run(main())