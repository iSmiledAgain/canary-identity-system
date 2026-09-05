"""Normalised event model shared by every stage of the engine.

CloudTrail records reach us in three different shapes:

1. Wrapped in an EventBridge envelope (``{"detail": {...}}``) - the live path.
2. A bare CloudTrail record - what ``LookupEvents`` and S3 log files contain.
3. A flattened row from CloudWatch Logs Insights (``userIdentity.userName``).

:class:`CanaryEvent` collapses all three into one structure so the analyzer,
profiler, timeline and alerter never have to care which door the event came in.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


def parse_timestamp(value: Any) -> datetime:
    """Best-effort parse of the many timestamp shapes CloudTrail emits.

    Falls back to epoch (rather than raising) so that one malformed record can
    never take down the whole detection pipeline.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # Logs Insights hands back epoch milliseconds.
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        for fmt in _TIME_FORMATS:
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.fromtimestamp(0, tz=timezone.utc)


def _dig(source: dict, *path: str, default: Any = None) -> Any:
    """Read a nested key, tolerating both nested dicts and dotted flat keys."""
    dotted = ".".join(path)
    if dotted in source:
        return source[dotted]
    cursor: Any = source
    for key in path:
        if not isinstance(cursor, dict) or key not in cursor:
            return default
        cursor = cursor[key]
    return cursor if cursor is not None else default


def _coerce_dict(value: Any) -> dict:
    """requestParameters arrives as a dict, a JSON string, or null."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


@dataclass
class CanaryEvent:
    """One CloudTrail API call, normalised."""

    event_name: str = "UnknownAction"
    event_source: str = ""
    event_time: datetime = field(
        default_factory=lambda: datetime.fromtimestamp(0, tz=timezone.utc)
    )
    source_ip: str = "unknown"
    user_agent: str = ""
    principal_name: str = "unknown"
    principal_arn: str = ""
    principal_type: str = ""
    access_key_id: str = ""
    account_id: str = ""
    aws_region: str = ""
    error_code: str = ""
    error_message: str = ""
    request_parameters: dict = field(default_factory=dict)
    session_issuer: str = ""
    mfa_authenticated: bool = False
    event_id: str = ""
    raw: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ parse
    @classmethod
    def from_event(cls, payload: dict) -> "CanaryEvent":
        """Build an event from an EventBridge envelope or a CloudTrail record."""
        if not isinstance(payload, dict):
            raise TypeError(f"expected a dict payload, got {type(payload).__name__}")

        detail = payload.get("detail")
        record = detail if isinstance(detail, dict) else payload

        identity = record.get("userIdentity")
        identity = identity if isinstance(identity, dict) else {}
        session_context = identity.get("sessionContext") or {}
        session_issuer = session_context.get("sessionIssuer") or {}
        attributes = session_context.get("attributes") or {}

        principal_name = (
            _dig(record, "userIdentity", "userName")
            or identity.get("userName")
            or session_issuer.get("userName")
            or cls._name_from_arn(
                _dig(record, "userIdentity", "arn") or identity.get("arn") or ""
            )
            or "unknown"
        )

        mfa = attributes.get("mfaAuthenticated")
        event = cls(
            event_name=record.get("eventName") or "UnknownAction",
            event_source=record.get("eventSource") or "",
            event_time=parse_timestamp(
                record.get("eventTime") or payload.get("time") or record.get("@timestamp")
            ),
            source_ip=record.get("sourceIPAddress") or "unknown",
            user_agent=record.get("userAgent") or "",
            principal_name=principal_name,
            principal_arn=_dig(record, "userIdentity", "arn", default="")
            or identity.get("arn", ""),
            principal_type=_dig(record, "userIdentity", "type", default="")
            or identity.get("type", ""),
            access_key_id=_dig(record, "userIdentity", "accessKeyId", default="")
            or identity.get("accessKeyId", ""),
            account_id=record.get("recipientAccountId")
            or _dig(record, "userIdentity", "accountId", default="")
            or payload.get("account", ""),
            aws_region=record.get("awsRegion") or payload.get("region", ""),
            error_code=record.get("errorCode") or "",
            error_message=record.get("errorMessage") or "",
            request_parameters=_coerce_dict(record.get("requestParameters")),
            session_issuer=session_issuer.get("arn", ""),
            mfa_authenticated=str(mfa).lower() == "true",
            event_id=record.get("eventID") or payload.get("id") or "",
            raw=payload,
        )
        if not event.event_id:
            event.event_id = event.fingerprint()
        return event

    @staticmethod
    def _name_from_arn(arn: str) -> str:
        return arn.rsplit("/", 1)[-1] if "/" in arn else ""

    # ------------------------------------------------------------------ helpers
    def fingerprint(self) -> str:
        """Stable id for de-duplicating the same call seen twice."""
        seed = f"{self.event_time.isoformat()}|{self.event_name}|{self.source_ip}|{self.principal_name}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    @property
    def denied(self) -> bool:
        return bool(self.error_code)

    @property
    def principal_id(self) -> str:
        """Preferred pivot label for this actor."""
        return self.principal_arn or self.principal_name

    def is_canary(self, prefixes: list[str], identities: list[str] | None = None) -> bool:
        """True when this call was made with one of our planted identities."""
        haystacks = [self.principal_name.lower(), self.principal_arn.lower()]
        if identities:
            wanted = {i.lower() for i in identities}
            if any(h and h in wanted for h in haystacks):
                return True
            if any(h.rsplit("/", 1)[-1] in wanted for h in haystacks if h):
                return True
        return any(
            h.startswith(p.lower()) or f"/{p.lower()}" in h
            for p in prefixes
            for h in haystacks
            if h
        )

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_time": self.event_time.isoformat().replace("+00:00", "Z"),
            "event_name": self.event_name,
            "event_source": self.event_source,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "principal_name": self.principal_name,
            "principal_arn": self.principal_arn,
            "principal_type": self.principal_type,
            "access_key_id": self.access_key_id,
            "account_id": self.account_id,
            "aws_region": self.aws_region,
            "error_code": self.error_code,
            "denied": self.denied,
        }
