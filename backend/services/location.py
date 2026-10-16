"""Location minimization: coarsen or withhold GPS coordinates.

Minimization levels:
  - none: return original coordinates
  - coarsen: snap to a grid cell (default 1km)
  - withhold: return None for coordinates, only grid cell
"""

import os
import math
import logging
from typing import Optional, Tuple

logger = logging.getLogger("vsoc.location")

MINIMIZATION_LEVEL = os.getenv("LOCATION_MINIMIZATION_LEVEL", "coarsen")
GRID_SIZE_KM = float(os.getenv("LOCATION_GRID_SIZE_KM", "1.0"))

# Approximate meters per degree at equator
METERS_PER_DEGREE_LAT = 111_320


def _grid_cell(lat: float, lon: float, size_km: float) -> str:
    """Compute a grid cell identifier for a location."""
    size_deg = size_km * 1000.0 / METERS_PER_DEGREE_LAT
    lat_cell = int(lat / size_deg)
    lon_cell = int(lon / size_deg)
    return f"grid:{lat_cell}:{lon_cell}"


def coarsen_location(
    latitude: float,
    longitude: float,
    minimization_level: Optional[str] = None,
    grid_size_km: Optional[float] = None,
) -> dict:
    """Apply location minimization policy.

    Returns a dict with original (if allowed), coarsened values, grid cell,
    minimization applied, and reason.
    """
    level = (minimization_level or MINIMIZATION_LEVEL).lower()
    size_km = grid_size_km or GRID_SIZE_KM

    if level not in ("none", "coarsen", "withhold"):
        level = "coarsen"

    grid_cell = _grid_cell(latitude, longitude, size_km)
    size_deg = size_km * 1000.0 / METERS_PER_DEGREE_LAT
    coarsened_lat = round(round(latitude / size_deg) * size_deg, 6)
    coarsened_lon = round(round(longitude / size_deg) * size_deg, 6)

    if level == "none":
        return {
            "original_latitude": latitude,
            "original_longitude": longitude,
            "coarsened_latitude": latitude,
            "coarsened_longitude": longitude,
            "grid_cell": grid_cell,
            "minimization_applied": "none",
            "reason": "Location minimization disabled; raw coordinates returned.",
        }

    if level == "coarsen":
        return {
            "original_latitude": None,
            "original_longitude": None,
            "coarsened_latitude": coarsened_lat,
            "coarsened_longitude": coarsened_lon,
            "grid_cell": grid_cell,
            "minimization_applied": "coarsen",
            "reason": (
                f"Coordinates coarsened to {size_km}km grid. "
                "Raw location withheld from ordinary alerts."
            ),
        }

    # withhold
    return {
        "original_latitude": None,
        "original_longitude": None,
        "coarsened_latitude": None,
        "coarsened_longitude": None,
        "grid_cell": grid_cell,
        "minimization_applied": "withhold",
        "reason": "Location withheld entirely; only grid cell provided.",
    }