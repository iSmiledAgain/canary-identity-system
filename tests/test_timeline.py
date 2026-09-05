"""Timeline reconstruction, log-source query building and failure handling."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.core.analyzer import analyze_event, analyze_many
from src.core.timeline import (
    AthenaLogSource,
    CloudWatchLogsInsightsSource,
    StaticLogSource,
    build_phases,
    reconstruct,
    source_from_config,
)


class ExplodingSource:
    name = "exploding"

    def fetch(self, pivots, start, end, limit):
        raise RuntimeError("query blew up")


def test_reconstructs_the_full_chain(attack_sequence, config):
    trigger = analyze_event(attack_sequence[-1], config)
    timeline = reconstruct(trigger, config, StaticLogSource(attack_sequence))

    assert len(timeline.events) == len(attack_sequence)
    assert timeline.chain[0] == "Discovery"
    assert "Privilege Escalation" in timeline.chain
    assert "Defense Evasion" in timeline.chain


def test_chain_has_no_consecutive_duplicates(attack_sequence, config):
    trigger = analyze_event(attack_sequence[-1], config)
    chain = reconstruct(trigger, config, StaticLogSource(attack_sequence)).chain
    assert all(a != b for a, b in zip(chain, chain[1:]))


def test_events_are_chronological(attack_sequence, config):
    trigger = analyze_event(attack_sequence[0], config)
    timeline = reconstruct(trigger, config, StaticLogSource(attack_sequence))
    stamps = [e.event.event_time for e in timeline.events]
    assert stamps == sorted(stamps)


def test_trigger_survives_a_backend_failure(canary_event, config):
    trigger = analyze_event(canary_event, config)
    timeline = reconstruct(trigger, config, ExplodingSource())

    assert len(timeline.events) == 1
    assert "query blew up" in timeline.note


def test_no_backend_still_yields_a_single_event_timeline(canary_event, config):
    trigger = analyze_event(canary_event, config)
    timeline = reconstruct(trigger, config, None)

    assert timeline.source == "unavailable"
    assert len(timeline.events) == 1
    assert "No log backend configured" in timeline.note


def test_pivots_exclude_unknown_values(config):
    trigger = analyze_event({"detail": {"eventName": "ListBuckets"}}, config)
    timeline = reconstruct(trigger, config, None)
    assert "source_ip" not in timeline.pivots


def test_unrelated_activity_is_excluded(attack_sequence, config):
    """A different actor entirely must not be pulled into the timeline."""
    unrelated = {
        "detail": dict(
            attack_sequence[0]["detail"],
            sourceIPAddress="203.0.113.9",
            eventID="ev-unrelated",
            userIdentity={
                "type": "IAMUser",
                "userName": "ci-deploy",
                "arn": "arn:aws:iam::123456789012:user/ci-deploy",
                "accessKeyId": "AKIAUNRELATEDKEY",
            },
        )
    }
    source = StaticLogSource(attack_sequence + [unrelated])
    trigger = analyze_event(attack_sequence[-1], config)

    timeline = reconstruct(trigger, config, source)
    assert "ev-unrelated" not in {e.event.event_id for e in timeline.events}
    assert len(timeline.events) == len(attack_sequence)


def test_same_key_from_a_new_ip_is_correlated(attack_sequence, config):
    """Pivoting on the access key catches the credential moving between hosts."""
    roaming = {
        "detail": dict(
            attack_sequence[0]["detail"],
            sourceIPAddress="203.0.113.9",
            eventID="ev-roaming",
            eventName="ListUsers",
        )
    }
    source = StaticLogSource(attack_sequence + [roaming])
    trigger = analyze_event(attack_sequence[-1], config)

    timeline = reconstruct(trigger, config, source)
    ips = {e.event.source_ip for e in timeline.events}

    assert "ev-roaming" in {e.event.event_id for e in timeline.events}
    assert ips == {"198.51.100.42", "203.0.113.9"}


def test_build_phases_groups_contiguous_tactics(attack_sequence, config):
    phases = build_phases(analyze_many(attack_sequence, config))

    assert phases[0].tactic == "Discovery"
    assert len(phases[0].actions) >= 2
    assert phases[0].started_at <= phases[0].ended_at


def test_render_ascii_draws_arrows(attack_sequence, config):
    trigger = analyze_event(attack_sequence[-1], config)
    rendered = reconstruct(trigger, config, StaticLogSource(attack_sequence)).render_ascii()

    assert "Discovery" in rendered
    assert "v" in rendered
    assert "GetSecretValue" in rendered


def test_render_ascii_handles_empty_timeline():
    from src.core.timeline import Timeline

    assert "no correlated activity" in Timeline().render_ascii()


def test_cloudwatch_query_filters_on_all_pivots():
    source = CloudWatchLogsInsightsSource("/aws/cloudtrail")
    query = source.build_query(
        {"source_ip": "198.51.100.42", "access_key_id": "AKIA1", "principal": "arn:aws:iam::1:user/x"},
        50,
    )
    assert 'sourceIPAddress = "198.51.100.42"' in query
    assert 'userIdentity.accessKeyId = "AKIA1"' in query
    assert "sort @timestamp asc" in query
    assert "limit 50" in query


def test_query_builders_strip_injection_characters():
    """Pivot values come from attacker-controlled fields, so they are sanitised."""
    source = CloudWatchLogsInsightsSource("/aws/cloudtrail")
    query = source.build_query({"source_ip": '1.1.1.1" or ""=="'}, 10)
    assert '""' not in query
    assert query.count('"') == 2  # only the two quotes we wrap the value in

    athena = AthenaLogSource("db", "tbl", "s3://out/")
    sql = athena.build_query(
        {"source_ip": "1.1.1.1' OR '1'='1"},
        datetime(2026, 9, 5, tzinfo=timezone.utc),
        datetime(2026, 9, 6, tzinfo=timezone.utc),
        10,
    )
    assert "OR '1'='1" not in sql


def test_athena_query_is_time_bounded():
    athena = AthenaLogSource("cloudtrail_db", "logs", "s3://results/")
    sql = athena.build_query(
        {"access_key_id": "AKIA1"},
        datetime(2026, 9, 5, tzinfo=timezone.utc),
        datetime(2026, 9, 6, tzinfo=timezone.utc),
        100,
    )
    assert "cloudtrail_db.logs" in sql
    assert "BETWEEN" in sql
    assert "LIMIT 100" in sql


def test_source_from_config_selects_backend():
    from src.core.config import Config

    assert source_from_config(Config(timeline_backend="none")) is None
    assert source_from_config(Config(timeline_backend="cloudwatch", log_group="")) is None

    cw = source_from_config(Config(timeline_backend="cloudwatch", log_group="/aws/ct"))
    assert isinstance(cw, CloudWatchLogsInsightsSource)

    athena = source_from_config(
        Config(
            timeline_backend="athena",
            athena_database="db",
            athena_output_location="s3://out/",
        )
    )
    assert isinstance(athena, AthenaLogSource)


class FakeLogsClient:
    """Minimal stub of the boto3 logs client used by the Insights source."""

    def __init__(self, statuses, results=None):
        self.statuses = list(statuses)
        self.results = results or []
        self.stopped = False

    def start_query(self, **kwargs):
        self.kwargs = kwargs
        return {"queryId": "q-1"}

    def get_query_results(self, queryId):  # noqa: N803 - boto3 casing
        status = self.statuses.pop(0)
        return {"status": status, "results": self.results if status == "Complete" else []}

    def stop_query(self, queryId):  # noqa: N803
        self.stopped = True


def test_cloudwatch_source_decodes_result_rows():
    rows = [
        [
            {"field": "eventTime", "value": "2026-09-05T03:14:10Z"},
            {"field": "eventName", "value": "ListBuckets"},
            {"field": "sourceIPAddress", "value": "198.51.100.42"},
            {"field": "userIdentity.userName", "value": "canary-prod-db-backup"},
        ]
    ]
    client = FakeLogsClient(["Running", "Complete"], rows)
    source = CloudWatchLogsInsightsSource("/aws/ct", client=client, poll_seconds=0)

    records = source.fetch(
        {"source_ip": "198.51.100.42"},
        datetime(2026, 9, 5, tzinfo=timezone.utc),
        datetime(2026, 9, 6, tzinfo=timezone.utc),
        10,
    )
    assert records[0]["eventName"] == "ListBuckets"
    assert records[0]["userIdentity"]["userName"] == "canary-prod-db-backup"


def test_cloudwatch_source_raises_on_failed_query():
    client = FakeLogsClient(["Failed"])
    source = CloudWatchLogsInsightsSource("/aws/ct", client=client, poll_seconds=0)

    with pytest.raises(RuntimeError):
        source.fetch({}, datetime.now(timezone.utc), datetime.now(timezone.utc), 10)


def test_to_dict_is_json_safe(attack_sequence, config):
    import json

    trigger = analyze_event(attack_sequence[-1], config)
    json.dumps(reconstruct(trigger, config, StaticLogSource(attack_sequence)).to_dict())


class FakeAthenaClient:
    """Minimal stub of the boto3 athena client."""

    def __init__(self, states, rows=None):
        self.states = list(states)
        self.rows = rows or []

    def start_query_execution(self, **kwargs):
        self.kwargs = kwargs
        return {"QueryExecutionId": "x-1"}

    def get_query_execution(self, QueryExecutionId):  # noqa: N803 - boto3 casing
        return {"QueryExecution": {"Status": {"State": self.states.pop(0)}}}

    def get_query_results(self, QueryExecutionId):  # noqa: N803
        return {"ResultSet": {"Rows": self.rows}}


def _athena_row(values):
    return {"Data": [{"VarCharValue": v} for v in values]}


def test_athena_source_decodes_result_rows():
    header = _athena_row(
        ["eventtime", "eventname", "sourceipaddress", "useragent", "username", "accesskeyid"]
    )
    row = _athena_row(
        [
            "2026-09-05T03:14:10Z",
            "AssumeRole",
            "198.51.100.42",
            "Boto3/1.34.11",
            "canary-prod-db-backup",
            "AKIAIOSFODNN7CANARY",
        ]
    )
    client = FakeAthenaClient(["RUNNING", "SUCCEEDED"], [header, row])
    source = AthenaLogSource("db", "logs", "s3://out/", client=client, poll_seconds=0)

    records = source.fetch(
        {"access_key_id": "AKIAIOSFODNN7CANARY"},
        datetime(2026, 9, 5, tzinfo=timezone.utc),
        datetime(2026, 9, 6, tzinfo=timezone.utc),
        10,
    )
    assert records[0]["eventName"] == "AssumeRole"
    assert records[0]["userIdentity"]["accessKeyId"] == "AKIAIOSFODNN7CANARY"


def test_athena_source_returns_empty_for_no_rows():
    client = FakeAthenaClient(["SUCCEEDED"], [])
    source = AthenaLogSource("db", "logs", "s3://out/", client=client, poll_seconds=0)

    assert source.fetch({}, datetime.now(timezone.utc), datetime.now(timezone.utc), 10) == []


def test_athena_source_raises_on_failure():
    client = FakeAthenaClient(["FAILED"])
    source = AthenaLogSource("db", "logs", "s3://out/", client=client, poll_seconds=0)

    with pytest.raises(RuntimeError):
        source.fetch({}, datetime.now(timezone.utc), datetime.now(timezone.utc), 10)


def test_cloudwatch_source_times_out_and_stops_the_query():
    client = FakeLogsClient(["Running"] * 50)
    source = CloudWatchLogsInsightsSource(
        "/aws/ct", client=client, poll_seconds=0, timeout_seconds=0
    )

    with pytest.raises(TimeoutError):
        source.fetch({}, datetime.now(timezone.utc), datetime.now(timezone.utc), 10)
    assert client.stopped is True


def test_logs_insights_row_prefers_the_raw_message():
    from src.core.timeline import _row_to_record

    record = _row_to_record(
        [{"field": "@message", "value": '{"eventName": "GetObject", "awsRegion": "eu-west-1"}'}]
    )
    assert record["eventName"] == "GetObject"
    assert record["awsRegion"] == "eu-west-1"


def test_logs_insights_row_falls_back_on_bad_json():
    from src.core.timeline import _row_to_record

    record = _row_to_record(
        [{"field": "@message", "value": "not json"}, {"field": "eventName", "value": "ListBuckets"}]
    )
    assert record["eventName"] == "ListBuckets"
