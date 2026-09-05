"""Event analysis: classification, tool fingerprinting and detection signals."""

from __future__ import annotations

import copy

from src.core.analyzer import analyze_event, analyze_many, extract_target, fingerprint_tool
from src.core.models import CanaryEvent


def test_analyzes_the_shared_mock_contract(canary_event, config):
    result = analyze_event(canary_event, config)

    assert result.is_canary is True
    assert result.event.event_name == "GetCallerIdentity"
    assert result.tactic == "Discovery"
    assert result.technique.technique_id == "T1087.004"
    assert result.severity == "CRITICAL"  # canary use alone is critical


def test_canary_signal_is_raised(canary_event, config):
    names = {s.name for s in analyze_event(canary_event, config).signals}
    assert "canary_identity_used" in names
    assert "access_denied" in names


def test_benign_identity_is_not_flagged_as_canary(benign_event, config):
    result = analyze_event(benign_event, config)

    assert result.is_canary is False
    assert "canary_identity_used" not in {s.name for s in result.signals}


def test_severity_escalates_with_signals(config):
    payload = {
        "detail": {
            "eventName": "ListBuckets",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2026-09-05T03:14:10Z",
            "sourceIPAddress": "198.51.100.42",
            "userAgent": "curl/8.4.0",
            "userIdentity": {"type": "IAMUser", "userName": "canary-prod-db-backup"},
        }
    }
    result = analyze_event(payload, config)
    assert result.technique.severity == "MEDIUM"
    assert result.severity == "CRITICAL"
    assert "suspicious_client" in {s.name for s in result.signals}


def test_missing_user_agent_is_suspicious():
    label, severity = fingerprint_tool("")
    assert severity == "HIGH"
    assert "Missing" in label


def test_offensive_tooling_is_fingerprinted():
    label, severity = fingerprint_tool("Pacu/1.6.0 Python/3.11")
    assert severity == "CRITICAL"
    assert "Pacu" in label


def test_ordinary_cli_is_not_its_own_signal():
    label, severity = fingerprint_tool("aws-cli/2.15.0 Python/3.11.6")
    assert severity is None
    assert label == "AWS CLI"


def test_extract_target_prefers_resource_keys():
    event = CanaryEvent(
        event_name="GetObject",
        request_parameters={"bucketName": "acme-prod-db-backups", "key": "dump.sql.gz"},
    )
    assert extract_target(event) == "acme-prod-db-backups/dump.sql.gz"


def test_extract_target_empty_when_no_parameters():
    assert extract_target(CanaryEvent(event_name="ListBuckets")) == ""


def test_summary_line_includes_action_and_tactic(canary_event, config):
    line = analyze_event(canary_event, config).summary_line()
    assert "GetCallerIdentity" in line
    assert "Discovery" in line
    assert "AccessDenied" in line


def test_analyze_many_sorts_and_deduplicates(attack_sequence, config):
    duplicated = attack_sequence + [copy.deepcopy(attack_sequence[0])]
    results = analyze_many(duplicated, config)

    assert len(results) == len(attack_sequence)
    stamps = [r.event.event_time for r in results]
    assert stamps == sorted(stamps)


def test_analyze_many_skips_malformed_records(attack_sequence, config):
    results = analyze_many(attack_sequence + ["garbage", 42], config)
    assert len(results) == len(attack_sequence)


def test_no_mfa_signal_on_sensitive_action(config):
    payload = {
        "detail": {
            "eventName": "AttachUserPolicy",
            "eventTime": "2026-09-05T03:15:00Z",
            "sourceIPAddress": "198.51.100.42",
            "userAgent": "aws-cli/2.15.0",
            "userIdentity": {"type": "IAMUser", "userName": "canary-prod-db-backup"},
        }
    }
    assert "no_mfa_on_sensitive_action" in {
        s.name for s in analyze_event(payload, config).signals
    }


def test_to_dict_is_json_safe(canary_event, config):
    import json

    json.dumps(analyze_event(canary_event, config).to_dict())
