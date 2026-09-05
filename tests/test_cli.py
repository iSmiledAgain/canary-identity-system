"""The offline CLI driver."""

from __future__ import annotations

import json

import pytest

from src.cli import main


@pytest.fixture(autouse=True)
def cli_env(monkeypatch):
    monkeypatch.setenv("CANARY_IDENTITY_PREFIXES", "canary-")
    monkeypatch.setenv("TIMELINE_BACKEND", "none")
    monkeypatch.setenv("ALERT_DRY_RUN", "true")


def test_demo_renders_a_console_report(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out

    assert "CANARY IDENTITY TRIGGERED" in out
    assert "RECONSTRUCTED TIMELINE" in out
    assert "AssumeRole" in out


def test_demo_json_output_is_parsable(capsys):
    assert main(["demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["severity"] == "CRITICAL"
    assert payload["timeline"]["event_count"] == 9


def test_slack_output_mode(capsys):
    assert main(["demo", "--output", "slack"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["blocks"][0]["type"] == "header"


def test_replay_of_the_shared_mock_contract(capsys, tmp_path):
    assert main(["replay", "tests/mock_cloudtrail_event.json"]) == 0
    assert "GetCallerIdentity" in capsys.readouterr().out


def test_replay_rejects_an_empty_file(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("[]")
    with pytest.raises(SystemExit):
        main(["replay", str(path)])


def test_replay_rejects_a_non_object_file(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('"just a string"')
    with pytest.raises(SystemExit):
        main(["replay", str(path)])
