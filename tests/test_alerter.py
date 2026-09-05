"""Alert formatting and delivery."""

from __future__ import annotations

import json

import pytest

from src.core import alerter
from src.core.alerter import (
    build_discord_payload,
    build_generic_payload,
    build_slack_payload,
    dispatch,
    render_console,
)
from src.core.config import Config
from src.core.incident import build_incident
from src.core.timeline import StaticLogSource


@pytest.fixture
def incident(attack_sequence, config):
    return build_incident(attack_sequence[-1], config, StaticLogSource(attack_sequence))


def test_slack_payload_is_valid_block_kit(incident):
    payload = build_slack_payload(incident)

    assert payload["text"]
    assert payload["blocks"][0]["type"] == "header"
    assert len(payload["blocks"][0]["text"]["text"]) <= 150
    assert all("type" in block for block in payload["blocks"])
    json.dumps(payload)


def test_slack_payload_respects_the_ten_field_limit(incident):
    """Slack rejects a section block carrying more than 10 fields."""
    sections = [b for b in build_slack_payload(incident)["blocks"] if b.get("fields")]
    assert sections
    assert all(len(s["fields"]) <= 10 for s in sections)


def test_slack_payload_carries_the_evidence(incident):
    text = json.dumps(build_slack_payload(incident))

    assert "canary-prod-db-backup" in text
    assert "198.51.100.42" in text
    assert "Privilege Escalation" in text
    assert incident.incident_id in text


def test_discord_payload_is_a_valid_embed(incident):
    payload = build_discord_payload(incident)
    embed = payload["embeds"][0]

    assert len(payload["embeds"]) == 1
    assert len(embed["fields"]) <= 25
    assert isinstance(embed["color"], int)
    assert all(len(f["value"]) <= 1024 for f in embed["fields"])
    json.dumps(payload)


def test_generic_payload_is_the_full_incident(incident):
    payload = build_generic_payload(incident)

    assert payload["incident_id"] == incident.incident_id
    assert payload["timeline"]["event_count"] == len(incident.timeline.events)
    json.dumps(payload, default=str)


def test_console_rendering_contains_the_timeline(incident):
    text = render_console(incident)

    assert "CANARY IDENTITY TRIGGERED" in text
    assert "RECONSTRUCTED TIMELINE" in text
    assert "RISK SCORING" in text
    assert "GetSecretValue" in text


def test_long_timelines_are_truncated():
    long_text = "\n".join(f"line {i}" for i in range(80))
    truncated = alerter._truncate_chain(long_text, 10)

    assert truncated.count("\n") == 10
    assert "more lines" in truncated


def test_dispatch_falls_back_to_console_without_sinks(incident, capsys):
    results = dispatch(incident, Config(dry_run=False, timeline_backend="none"))

    assert [r.channel for r in results] == ["console"]
    assert "CANARY IDENTITY TRIGGERED" in capsys.readouterr().out


def test_dispatch_posts_to_every_configured_sink(incident, monkeypatch):
    calls = []

    def fake_post(url, payload, timeout=10):
        calls.append((url, payload))
        return alerter.DeliveryResult("webhook", True, 200)

    monkeypatch.setattr(alerter, "post_json", fake_post)
    config = Config(
        slack_webhook_url="https://hooks.slack.test/a",
        discord_webhook_url="https://discord.test/b",
        generic_webhook_url="https://siem.test/c",
        dry_run=False,
    )
    results = dispatch(incident, config)

    assert [r.channel for r in results] == ["slack", "discord", "webhook"]
    assert len(calls) == 3


def test_delivery_failure_is_reported_not_raised(incident, monkeypatch):
    def boom(request, timeout=10):
        raise RuntimeError("network down")

    monkeypatch.setattr(alerter.urllib.request, "urlopen", boom)
    result = alerter.post_json("https://hooks.slack.test/a", {"text": "hi"})

    assert result.ok is False
    assert "network down" in result.error


def test_post_json_sends_a_json_content_type(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout=10):
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.data)
        return FakeResponse()

    monkeypatch.setattr(alerter.urllib.request, "urlopen", fake_urlopen)
    result = alerter.post_json("https://hooks.slack.test/a", {"text": "hi"})

    assert result.ok is True
    assert captured["headers"]["Content-type"] == "application/json"
    assert captured["body"] == {"text": "hi"}
