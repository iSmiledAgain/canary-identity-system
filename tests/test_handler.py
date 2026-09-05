"""Lambda handler wiring and the end-to-end pipeline."""

from __future__ import annotations

import json

import pytest

from src import handler
from src.core.config import Config
from src.core.incident import build_incident
from src.core.timeline import StaticLogSource


@pytest.fixture(autouse=True)
def dry_run_env(monkeypatch):
    monkeypatch.setenv("CANARY_IDENTITY_PREFIXES", "canary-")
    monkeypatch.setenv("TIMELINE_BACKEND", "none")
    monkeypatch.setenv("ALERT_DRY_RUN", "true")
    monkeypatch.setenv("DEPLOY_ENVIRONMENT", "test")


def test_handler_alerts_on_a_canary_event(canary_event):
    result = handler.lambda_handler(canary_event, None)

    assert result["statusCode"] == 200
    assert result["received"] == 1
    assert result["alerted"] == 1
    assert result["incidents"][0]["severity"] == "CRITICAL"
    assert result["incidents"][0]["principal"] == "canary-prod-db-backup"


def test_handler_suppresses_non_canary_activity(benign_event):
    result = handler.lambda_handler(benign_event, None)

    assert result["received"] == 1
    assert result["alerted"] == 0
    assert result["incidents"][0]["suppressed"] is True


def test_handler_processes_an_sqs_batch(canary_event):
    batch = {"Records": [{"body": json.dumps(canary_event)}, {"body": json.dumps(canary_event)}]}
    result = handler.lambda_handler(batch, None)

    assert result["received"] == 2
    assert result["alerted"] == 2


def test_handler_survives_one_bad_record(canary_event):
    batch = {"Records": [{"body": json.dumps(canary_event)}, "not-a-dict"]}
    result = handler.lambda_handler(batch, None)

    assert result["received"] == 2
    assert any("error" in item for item in result["incidents"])
    assert result["alerted"] == 1


def test_handler_returns_a_json_serialisable_body(canary_event):
    json.dumps(handler.lambda_handler(canary_event, None))


def test_empty_payload_does_not_crash():
    result = handler.lambda_handler({}, None)
    assert result["statusCode"] == 200


def test_end_to_end_incident_shape(attack_sequence):
    """The pipeline contract Person A's infrastructure depends on."""
    config = Config(canary_prefixes=["canary-"], timeline_backend="none", dry_run=True)
    incident = build_incident(attack_sequence[-1], config, StaticLogSource(attack_sequence))

    assert incident.incident_id.startswith("CAN-")
    assert incident.severity == "CRITICAL"
    assert incident.suppressed is False
    assert incident.profile.risk_score >= 80
    assert incident.timeline.chain[0] == "Discovery"
    assert "Defense Evasion" in incident.timeline.chain

    payload = incident.to_dict()
    for key in ("incident_id", "severity", "trigger", "profile", "timeline"):
        assert key in payload
    json.dumps(payload, default=str)


def test_incident_suppression_explains_itself(benign_event):
    config = Config(canary_prefixes=["canary-"], timeline_backend="none")
    incident = build_incident(benign_event, config)

    assert incident.suppressed is True
    assert "not a registered canary identity" in incident.suppression_reason
