"""Behavioural profiling and risk scoring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.core.analyzer import analyze_event, analyze_many
from src.core.profiler import profile_actor


def _event(name: str, offset: int, *, denied: bool = False, ip: str = "198.51.100.42",
           user: str = "canary-prod-db-backup", ua: str = "Boto3/1.34.11") -> dict:
    stamp = (datetime(2026, 9, 5, 3, 14, 10, tzinfo=timezone.utc)
             + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
    detail = {
        "eventName": name,
        "eventTime": stamp,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "userIdentity": {
            "type": "IAMUser",
            "userName": user,
            "arn": f"arn:aws:iam::123456789012:user/{user}",
            "accessKeyId": "AKIAIOSFODNN7CANARY",
        },
    }
    if denied:
        detail["errorCode"] = "AccessDenied"
    return {"detail": detail}


def test_empty_input_returns_empty_profile():
    profile = profile_actor([])
    assert profile.event_count == 0
    assert profile.risk_score == 0


def test_full_attack_sequence_scores_high(attack_sequence, config):
    profile = profile_actor(analyze_many(attack_sequence, config))

    assert profile.event_count == len(attack_sequence)
    assert profile.source_ips == ["198.51.100.42"]
    assert profile.risk_score >= 80
    assert profile.max_severity == "CRITICAL"
    assert "Discovery" in profile.tactics
    assert "Privilege Escalation" in profile.tactics


def test_tactics_are_sorted_along_the_kill_chain(attack_sequence, config):
    from src.core import mitre

    profile = profile_actor(analyze_many(attack_sequence, config))
    ranks = [mitre.tactic_rank(t) for t in profile.tactics]
    assert ranks == sorted(ranks)


def test_regular_cadence_is_detected_as_automation(config):
    events = [analyze_event(_event("ListBuckets", i * 10), config) for i in range(6)]
    profile = profile_actor(events)

    assert profile.automated is True
    assert any("jitter" in r or "Machine-speed" in r for r in profile.risk_reasons)


def test_irregular_cadence_is_not_automation(config):
    offsets = [0, 47, 51, 300, 900, 1500]
    events = [analyze_event(_event("ListBuckets", o), config) for o in offsets]
    assert profile_actor(events).automated is False


def test_denied_sweep_is_labelled_enumeration(config):
    events = [
        analyze_event(_event(name, i * 30, denied=True), config)
        for i, name in enumerate(
            ["ListBuckets", "ListTables", "ListQueues", "ListTopics", "ListKeys", "ListFunctions"]
        )
    ]
    profile = profile_actor(events)

    assert profile.denied_ratio == 1.0
    assert "enumeration" in profile.behaviour.lower()


def test_single_probe_is_credential_validation(config):
    profile = profile_actor([analyze_event(_event("GetCallerIdentity", 0), config)])
    assert "validation" in profile.behaviour.lower()


def test_exfiltration_dominates_the_behaviour_label(config):
    events = [
        analyze_event(_event("ListBuckets", 0), config),
        analyze_event(_event("CopyObject", 30), config),
    ]
    assert "exfiltration" in profile_actor(events).behaviour.lower()


def test_multiple_ips_add_risk(config):
    single = profile_actor([analyze_event(_event("ListBuckets", i * 30), config) for i in range(3)])
    multi = profile_actor(
        [
            analyze_event(_event("ListBuckets", 0, ip="198.51.100.42"), config),
            analyze_event(_event("ListBuckets", 30, ip="203.0.113.9"), config),
            analyze_event(_event("ListBuckets", 60, ip="192.0.2.7"), config),
        ]
    )
    assert multi.risk_score > single.risk_score
    assert any("distinct IPs" in r for r in multi.risk_reasons)


def test_non_canary_activity_scores_lower(config):
    canary = profile_actor([analyze_event(_event("AssumeRole", 0), config)])
    normal = profile_actor(
        [analyze_event(_event("AssumeRole", 0, user="ci-deploy-role"), config)]
    )
    assert canary.risk_score > normal.risk_score


def test_risk_score_is_capped_at_100(attack_sequence, config):
    events = analyze_many(attack_sequence, config)
    assert 0 <= profile_actor(events).risk_score <= 100


def test_every_risk_point_has_a_reason(attack_sequence, config):
    profile = profile_actor(analyze_many(attack_sequence, config))
    assert profile.risk_score > 0
    assert profile.risk_reasons


def test_to_dict_is_json_safe(attack_sequence, config):
    import json

    json.dumps(profile_actor(analyze_many(attack_sequence, config)).to_dict())
