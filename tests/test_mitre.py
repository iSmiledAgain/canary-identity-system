"""ATT&CK mapping table and its heuristic fallbacks."""

from __future__ import annotations

import pytest

from src.core import mitre


@pytest.mark.parametrize(
    "action,tactic",
    [
        ("GetCallerIdentity", "Discovery"),
        ("ListBuckets", "Discovery"),
        ("ListAttachedUserPolicies", "Discovery"),
        ("GetSecretValue", "Credential Access"),
        ("AssumeRole", "Privilege Escalation"),
        ("AttachUserPolicy", "Privilege Escalation"),
        ("CreateAccessKey", "Persistence"),
        ("StopLogging", "Defense Evasion"),
        ("SendCommand", "Lateral Movement"),
        ("GetObject", "Collection"),
        ("CopyObject", "Exfiltration"),
        ("DeleteBucket", "Impact"),
    ],
)
def test_known_actions_map_to_expected_tactic(action, tactic):
    assert mitre.classify(action).tactic == tactic


def test_every_mapped_technique_has_a_valid_severity():
    for technique in mitre.ACTION_MAP.values():
        assert technique.severity in mitre.SEVERITY_ORDER


def test_every_mapped_technique_has_a_known_tactic():
    for technique in mitre.ACTION_MAP.values():
        assert technique.tactic in mitre.TACTIC_ORDER


@pytest.mark.parametrize(
    "action,tactic",
    [
        ("DescribeSomethingNew", "Discovery"),
        ("AssumeFutureRole", "Privilege Escalation"),
        ("DeleteEverything", "Impact"),
        ("InvokeSomething", "Lateral Movement"),
    ],
)
def test_unknown_actions_fall_back_by_verb(action, tactic):
    assert mitre.classify(action).tactic == tactic


def test_totally_unknown_action_is_unclassified():
    assert mitre.classify("Xyzzy").technique_id == "T0000"


def test_empty_action_is_unclassified():
    assert mitre.classify("") is mitre.UNCLASSIFIED


def test_query_is_collection_only_on_dynamodb():
    assert mitre.classify("Query", "dynamodb.amazonaws.com").tactic == "Collection"
    assert mitre.classify("Query", "route53.amazonaws.com").tactic == "Discovery"


def test_highest_severity_picks_the_worst():
    assert mitre.highest_severity(["LOW", "CRITICAL", "MEDIUM"]) == "CRITICAL"
    assert mitre.highest_severity([]) == "INFO"


def test_severity_rank_handles_garbage():
    assert mitre.severity_rank("nonsense") == 0


def test_tactic_rank_orders_the_kill_chain():
    assert mitre.tactic_rank("Discovery") < mitre.tactic_rank("Exfiltration")
    assert mitre.tactic_rank("Unclassified") == len(mitre.TACTIC_ORDER)


def test_technique_label_format():
    technique = mitre.classify("AssumeRole")
    assert technique.label.startswith("T1548")
    assert " - " in technique.label
