"""Shared pytest fixtures. No AWS credentials or network access required."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.core.config import Config  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Stop a developer's real environment from leaking into the tests."""
    for name in (
        "CANARY_IDENTITY_PREFIXES",
        "CANARY_IDENTITIES",
        "TIMELINE_BACKEND",
        "CLOUDTRAIL_LOG_GROUP",
        "ATHENA_DATABASE",
        "ATHENA_OUTPUT_LOCATION",
        "SLACK_WEBHOOK_URL",
        "DISCORD_WEBHOOK_URL",
        "GENERIC_WEBHOOK_URL",
        "ALERT_DRY_RUN",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def config() -> Config:
    return Config(
        canary_prefixes=["canary-"],
        timeline_backend="none",
        dry_run=True,
        environment="test",
    )


@pytest.fixture
def canary_event() -> dict:
    with (Path(__file__).resolve().parent / "mock_cloudtrail_event.json").open() as fh:
        return json.load(fh)


@pytest.fixture
def attack_sequence() -> list[dict]:
    with (FIXTURES / "attack_sequence.json").open() as fh:
        return json.load(fh)


@pytest.fixture
def benign_event() -> dict:
    with (FIXTURES / "benign_event.json").open() as fh:
        return json.load(fh)
