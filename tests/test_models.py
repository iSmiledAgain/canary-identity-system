"""CanaryEvent normalisation across every payload shape we accept."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.core.models import CanaryEvent, parse_timestamp


def test_parses_eventbridge_envelope(canary_event):
    event = CanaryEvent.from_event(canary_event)

    assert event.event_name == "GetCallerIdentity"
    assert event.principal_name == "canary-prod-db-backup"
    assert event.access_key_id == "AKIAIOSFODNN7CANARY"
    assert event.source_ip == "198.51.100.42"
    assert event.account_id == "123456789012"
    assert event.error_code == "AccessDenied"
    assert event.denied is True


def test_parses_bare_cloudtrail_record(canary_event):
    """A record with no EventBridge envelope must parse identically."""
    bare = canary_event["detail"]
    event = CanaryEvent.from_event(bare)

    assert event.event_name == "GetCallerIdentity"
    assert event.principal_name == "canary-prod-db-backup"


def test_parses_flattened_logs_insights_row():
    flat = {
        "eventTime": "2026-09-05T03:14:10Z",
        "eventName": "ListBuckets",
        "sourceIPAddress": "198.51.100.42",
        "userIdentity.userName": "canary-prod-db-backup",
        "userIdentity.accessKeyId": "AKIAIOSFODNN7CANARY",
        "userIdentity.arn": "arn:aws:iam::123456789012:user/canary-prod-db-backup",
    }
    event = CanaryEvent.from_event(flat)

    assert event.principal_name == "canary-prod-db-backup"
    assert event.access_key_id == "AKIAIOSFODNN7CANARY"


def test_assumed_role_falls_back_to_session_issuer(benign_event):
    event = CanaryEvent.from_event(benign_event)

    assert event.principal_type == "AssumedRole"
    assert event.principal_name in {"ci-deploy-role", "ci-deploy"}
    assert event.mfa_authenticated is False


def test_request_parameters_accept_json_string():
    event = CanaryEvent.from_event(
        {"eventName": "GetObject", "requestParameters": '{"bucketName": "acme-prod"}'}
    )
    assert event.request_parameters["bucketName"] == "acme-prod"


def test_malformed_request_parameters_degrade_to_empty():
    event = CanaryEvent.from_event({"eventName": "GetObject", "requestParameters": "not json"})
    assert event.request_parameters == {}


@pytest.mark.parametrize(
    "value,expected_year",
    [
        ("2026-09-05T03:14:10Z", 2026),
        ("2026-09-05T03:14:10.123Z", 2026),
        ("2026-09-05 03:14:10", 2026),
        (1757042050, 2025),
        ("total nonsense", 1970),
    ],
)
def test_timestamp_parsing_never_raises(value, expected_year):
    assert parse_timestamp(value).year == expected_year


def test_timestamps_are_timezone_aware(canary_event):
    assert CanaryEvent.from_event(canary_event).event_time.tzinfo is not None


def test_is_canary_matches_prefix_and_arn(canary_event, benign_event):
    assert CanaryEvent.from_event(canary_event).is_canary(["canary-"]) is True
    assert CanaryEvent.from_event(benign_event).is_canary(["canary-"]) is False


def test_is_canary_matches_explicit_identity_list(benign_event):
    event = CanaryEvent.from_event(benign_event)
    assert event.is_canary([], ["ci-deploy-role"]) is True


def test_fingerprint_is_stable_and_distinct():
    a = CanaryEvent(event_name="ListBuckets", source_ip="1.1.1.1")
    b = CanaryEvent(event_name="ListBuckets", source_ip="1.1.1.1")
    c = CanaryEvent(event_name="GetObject", source_ip="1.1.1.1")

    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != c.fingerprint()


def test_non_dict_payload_rejected():
    with pytest.raises(TypeError):
        CanaryEvent.from_event("not a dict")


def test_to_dict_is_json_safe(canary_event):
    import json

    json.dumps(CanaryEvent.from_event(canary_event).to_dict())
