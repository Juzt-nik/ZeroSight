"""Tests for detection module."""

import asyncio
import pytest
from backend.services.model_service import ModelService
from backend.services.preprocessing import parse_can_line


def test_parse_can_line():
    line = "1478198376.389427,0316,8,05,21,68,09,21,21,00,6f,R"
    parsed = parse_can_line(line)
    assert parsed["timestamp"] == 1478198376.389427
    assert parsed["arbitration_id"] == "0316"
    assert parsed["dlc"] == 8
    assert parsed["label"] == "R"


def test_parse_can_line_malformed():
    with pytest.raises(ValueError):
        parse_can_line("too,few,fields")


def test_model_initializes():
    service = ModelService(model_dir="./models", dataset_dir="./data/raw")
    asyncio.run(service.initialize())
    assert service.is_loaded() or service.model is not None