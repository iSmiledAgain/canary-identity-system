"""Stage 3: reconstruct the attack timeline around a canary hit.

When a trap fires we only see one API call. This module pivots on the
attacker's source IP and access key, pulls everything else they did inside the
lookback window, and folds it into an ordered kill chain.

Three log backends are supported behind one interface:

* :class:`CloudWatchLogsInsightsSource` - CloudTrail delivered to CloudWatch Logs.
* :class:`AthenaLogSource` - CloudTrail delivered to S3, queried with SQL.
* :class:`StaticLogSource` - an in-memory list, used by tests and the CLI demo.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from . import mitre
from .analyzer import AnalyzedEvent, analyze_many
from .config import Config


class LogSource(Protocol):
    """Anything that can return raw CloudTrail records for a set of pivots."""

    name: str

    def fetch(
        self, pivots: dict[str, str], start: datetime, end: datetime, limit: int
    ) -> list[dict]:
        ...


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class StaticLogSource:
    """In-memory log source. Filters a fixed record list by the pivots."""

    name = "static"

    def __init__(self, records: list[dict]):
        self._records = records

    def fetch(
        self, pivots: dict[str, str], start: datetime, end: datetime, limit: int
    ) -> list[dict]:
        from .models import CanaryEvent  # local import to avoid a cycle at import time

        matched: list[dict] = []
        for record in self._records:
            try:
                event = CanaryEvent.from_event(record)
            except (TypeError, AttributeError):
                continue
            if not (start <= event.event_time <= end):
                continue
            if pivots.get("source_ip") and event.source_ip == pivots["source_ip"]:
                matched.append(record)
            elif pivots.get("access_key_id") and event.access_key_id == pivots["access_key_id"]:
                matched.append(record)
            elif pivots.get("principal") and event.principal_id == pivots["principal"]:
                matched.append(record)
        return matched[:limit]


class CloudWatchLogsInsightsSource:
    """Queries CloudTrail records that CloudTrail delivers to CloudWatch Logs."""

    name = "cloudwatch-logs-insights"

    FIELDS = (
        "fields @timestamp, eventTime, eventName, eventSource, awsRegion, "
        "sourceIPAddress, userAgent, errorCode, errorMessage, "
        "userIdentity.type, userIdentity.userName, userIdentity.arn, "
        "userIdentity.accessKeyId, userIdentity.accountId, requestParameters"
    )

    def __init__(self, log_group: str, client=None, poll_seconds: float = 1.0,
                 timeout_seconds: int = 45):
        self.log_group = log_group
        self._client = client
        self.poll_seconds = poll_seconds
        self.timeout_seconds = timeout_seconds

    @property
    def client(self):
        if self._client is None:
            import boto3  # imported lazily so unit tests never need boto3

            self._client = boto3.client("logs")
        return self._client

    def build_query(self, pivots: dict[str, str], limit: int) -> str:
        clauses = []
        if pivots.get("source_ip"):
            clauses.append(f'sourceIPAddress = "{_escape(pivots["source_ip"])}"')
        if pivots.get("access_key_id"):
            clauses.append(
                f'userIdentity.accessKeyId = "{_escape(pivots["access_key_id"])}"'
            )
        if pivots.get("principal"):
            clauses.append(f'userIdentity.arn = "{_escape(pivots["principal"])}"')
        where = " or ".join(clauses) if clauses else "1 = 1"
        return (
            f"{self.FIELDS}\n"
            f"| filter {where}\n"
            f"| sort @timestamp asc\n"
            f"| limit {limit}"
        )

    def fetch(
        self, pivots: dict[str, str], start: datetime, end: datetime, limit: int
    ) -> list[dict]:
        started = self.client.start_query(
            logGroupName=self.log_group,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=self.build_query(pivots, limit),
            limit=limit,
        )
        query_id = started["queryId"]
        deadline = time.time() + self.timeout_seconds

        while time.time() < deadline:
            result = self.client.get_query_results(queryId=query_id)
            status = result.get("status")
            if status == "Complete":
                return [_row_to_record(row) for row in result.get("results", [])]
            if status in {"Failed", "Cancelled", "Timeout"}:
                raise RuntimeError(f"Logs Insights query {status}: {query_id}")
            time.sleep(self.poll_seconds)

        try:
            self.client.stop_query(queryId=query_id)
        except Exception:  # pragma: no cover - best-effort cleanup
            pass
        raise TimeoutError(f"Logs Insights query timed out after {self.timeout_seconds}s")


class AthenaLogSource:
    """Queries CloudTrail logs parked in S3 through Amazon Athena."""

    name = "athena"

    def __init__(self, database: str, table: str, output_location: str, client=None,
                 poll_seconds: float = 1.5, timeout_seconds: int = 60):
        self.database = database
        self.table = table
        self.output_location = output_location
        self._client = client
        self.poll_seconds = poll_seconds
        self.timeout_seconds = timeout_seconds

    @property
    def client(self):
        if self._client is None:
            import boto3  # lazy: keeps the unit tests dependency-free

            self._client = boto3.client("athena")
        return self._client

    def build_query(self, pivots: dict[str, str], start: datetime, end: datetime,
                    limit: int) -> str:
        clauses = []
        if pivots.get("source_ip"):
            clauses.append(f"sourceipaddress = '{_escape(pivots['source_ip'])}'")
        if pivots.get("access_key_id"):
            clauses.append(
                f"useridentity.accesskeyid = '{_escape(pivots['access_key_id'])}'"
            )
        if pivots.get("principal"):
            clauses.append(f"useridentity.arn = '{_escape(pivots['principal'])}'")
        where = " OR ".join(clauses) if clauses else "1 = 1"
        return (
            "SELECT eventtime, eventname, eventsource, awsregion, sourceipaddress, "
            "useragent, errorcode, useridentity.type, useridentity.username, "
            "useridentity.arn, useridentity.accesskeyid, requestparameters "
            f"FROM {self.database}.{self.table} "
            f"WHERE ({where}) "
            f"AND from_iso8601_timestamp(eventtime) "
            f"BETWEEN from_iso8601_timestamp('{start.isoformat()}') "
            f"AND from_iso8601_timestamp('{end.isoformat()}') "
            f"ORDER BY eventtime ASC LIMIT {limit}"
        )

    def fetch(
        self, pivots: dict[str, str], start: datetime, end: datetime, limit: int
    ) -> list[dict]:
        started = self.client.start_query_execution(
            QueryString=self.build_query(pivots, start, end, limit),
            QueryExecutionContext={"Database": self.database},
            ResultConfiguration={"OutputLocation": self.output_location},
        )
        execution_id = started["QueryExecutionId"]
        deadline = time.time() + self.timeout_seconds

        while time.time() < deadline:
            state = self.client.get_query_execution(QueryExecutionId=execution_id)
            status = state["QueryExecution"]["Status"]["State"]
            if status == "SUCCEEDED":
                results = self.client.get_query_results(QueryExecutionId=execution_id)
                return _athena_rows_to_records(results)
            if status in {"FAILED", "CANCELLED"}:
                raise RuntimeError(f"Athena query {status}: {execution_id}")
            time.sleep(self.poll_seconds)
        raise TimeoutError(f"Athena query timed out after {self.timeout_seconds}s")


# --------------------------------------------------------------------------- #
# Row decoding helpers
# --------------------------------------------------------------------------- #
def _escape(value: str) -> str:
    return value.replace('"', "").replace("'", "").replace("\n", "")


def _row_to_record(row: list[dict]) -> dict:
    """Turn a Logs Insights result row into a flat CloudTrail-ish record."""
    flat = {item["field"]: item["value"] for item in row if "field" in item}
    if "@message" in flat:
        try:
            return json.loads(flat["@message"])
        except json.JSONDecodeError:
            pass
    return {
        "eventTime": flat.get("eventTime") or flat.get("@timestamp"),
        "eventName": flat.get("eventName"),
        "eventSource": flat.get("eventSource"),
        "awsRegion": flat.get("awsRegion"),
        "sourceIPAddress": flat.get("sourceIPAddress"),
        "userAgent": flat.get("userAgent"),
        "errorCode": flat.get("errorCode"),
        "errorMessage": flat.get("errorMessage"),
        "requestParameters": flat.get("requestParameters"),
        "userIdentity": {
            "type": flat.get("userIdentity.type"),
            "userName": flat.get("userIdentity.userName"),
            "arn": flat.get("userIdentity.arn"),
            "accessKeyId": flat.get("userIdentity.accessKeyId"),
            "accountId": flat.get("userIdentity.accountId"),
        },
    }


def _athena_rows_to_records(results: dict) -> list[dict]:
    rows = results.get("ResultSet", {}).get("Rows", [])
    if not rows:
        return []
    header = [c.get("VarCharValue", "") for c in rows[0].get("Data", [])]
    records = []
    for row in rows[1:]:
        values = [c.get("VarCharValue", "") for c in row.get("Data", [])]
        flat = dict(zip(header, values))
        records.append(
            {
                "eventTime": flat.get("eventtime"),
                "eventName": flat.get("eventname"),
                "eventSource": flat.get("eventsource"),
                "awsRegion": flat.get("awsregion"),
                "sourceIPAddress": flat.get("sourceipaddress"),
                "userAgent": flat.get("useragent"),
                "errorCode": flat.get("errorcode"),
                "requestParameters": flat.get("requestparameters"),
                "userIdentity": {
                    "type": flat.get("type"),
                    "userName": flat.get("username"),
                    "arn": flat.get("arn"),
                    "accessKeyId": flat.get("accesskeyid"),
                },
            }
        )
    return records


# --------------------------------------------------------------------------- #
# Timeline assembly
# --------------------------------------------------------------------------- #
@dataclass
class Phase:
    """A contiguous run of activity belonging to one ATT&CK tactic."""

    tactic: str
    started_at: datetime
    ended_at: datetime
    actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic,
            "started_at": self.started_at.isoformat().replace("+00:00", "Z"),
            "ended_at": self.ended_at.isoformat().replace("+00:00", "Z"),
            "actions": self.actions,
        }


@dataclass
class Timeline:
    """The reconstructed attack path around a canary trigger."""

    events: list[AnalyzedEvent] = field(default_factory=list)
    phases: list[Phase] = field(default_factory=list)
    pivots: dict[str, str] = field(default_factory=dict)
    source: str = "unavailable"
    lookback_hours: int = 0
    note: str = ""

    @property
    def chain(self) -> list[str]:
        """Ordered, de-duplicated tactic chain, e.g. Discovery -> Privilege Escalation."""
        chain: list[str] = []
        for phase in self.phases:
            if not chain or chain[-1] != phase.tactic:
                chain.append(phase.tactic)
        return chain

    def render_ascii(self) -> str:
        """The vertical kill-chain diagram used in alerts and the CLI."""
        if not self.phases:
            return "(no correlated activity found)"
        lines = []
        for index, phase in enumerate(self.phases):
            stamp = phase.started_at.strftime("%H:%M:%S")
            lines.append(f"{stamp}  {phase.tactic}")
            for action in phase.actions:
                lines.append(f"          - {action}")
            if index < len(self.phases) - 1:
                lines.append("             |")
                lines.append("             v")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "pivots": self.pivots,
            "lookback_hours": self.lookback_hours,
            "event_count": len(self.events),
            "chain": self.chain,
            "phases": [p.to_dict() for p in self.phases],
            "events": [e.to_dict() for e in self.events],
            "note": self.note,
        }


def build_phases(events: list[AnalyzedEvent]) -> list[Phase]:
    """Group chronologically ordered events into contiguous tactic phases."""
    phases: list[Phase] = []
    for item in sorted(events, key=lambda e: e.event.event_time):
        stamp = item.event.event_time
        if phases and phases[-1].tactic == item.tactic:
            phases[-1].ended_at = stamp
            phases[-1].actions.append(item.summary_line(include_tactic=False))
        else:
            phases.append(
                Phase(
                    tactic=item.tactic,
                    started_at=stamp,
                    ended_at=stamp,
                    actions=[item.summary_line(include_tactic=False)],
                )
            )
    return phases


def source_from_config(config: Config) -> LogSource | None:
    """Pick a log backend from configuration. Returns None when disabled."""
    backend = config.timeline_backend
    if backend == "cloudwatch" and config.log_group:
        return CloudWatchLogsInsightsSource(
            config.log_group, timeout_seconds=config.query_timeout_seconds
        )
    if backend == "athena" and config.athena_database and config.athena_output_location:
        return AthenaLogSource(
            config.athena_database,
            config.athena_table,
            config.athena_output_location,
            timeout_seconds=config.query_timeout_seconds,
        )
    return None


def reconstruct(
    trigger: AnalyzedEvent,
    config: Config | None = None,
    source: LogSource | None = None,
) -> Timeline:
    """Rebuild the attack path around ``trigger``.

    The trigger event is always included, so a failure to reach the log backend
    degrades to a single-event timeline rather than losing the alert entirely.
    """
    config = config or Config.from_env()
    source = source or source_from_config(config)

    pivots = {
        "source_ip": trigger.event.source_ip,
        "access_key_id": trigger.event.access_key_id,
        "principal": trigger.event.principal_id,
    }
    pivots = {k: v for k, v in pivots.items() if v and v != "unknown"}

    end = trigger.event.event_time + timedelta(minutes=5)
    start = trigger.event.event_time - timedelta(hours=config.lookback_hours)

    timeline = Timeline(
        pivots=pivots,
        lookback_hours=config.lookback_hours,
        source=source.name if source else "unavailable",
    )

    records: list[dict] = []
    if source is None:
        timeline.note = (
            "No log backend configured (set CLOUDTRAIL_LOG_GROUP or Athena vars); "
            "reporting the trigger event only."
        )
    else:
        try:
            records = source.fetch(pivots, start, end, config.max_timeline_events)
        except Exception as exc:  # noqa: BLE001 - never lose the alert over a query
            timeline.note = f"Timeline query failed ({type(exc).__name__}: {exc}); reporting the trigger event only."

    correlated = analyze_many(records, config)
    known = {e.event.event_id for e in correlated}
    if trigger.event.event_id not in known:
        correlated.append(trigger)

    timeline.events = sorted(correlated, key=lambda e: e.event.event_time)
    timeline.phases = build_phases(timeline.events)
    return timeline


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)
