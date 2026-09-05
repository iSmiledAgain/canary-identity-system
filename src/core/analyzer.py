"""Stage 1: parse a CloudTrail event and classify what the attacker just did.

The analyzer answers three questions about a single API call:

* **Who** - which principal, from which IP, with which tool.
* **What** - which action, against which concrete resource.
* **So what** - which ATT&CK technique, at which severity, with which signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import mitre
from .config import Config
from .models import CanaryEvent

# User-agent substrings that betray offensive tooling or raw SDK scripting.
_TOOL_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("pacu", "Pacu (AWS exploitation framework)", "CRITICAL"),
    ("stratus", "Stratus Red Team", "HIGH"),
    ("cloudfox", "CloudFox (offensive recon)", "CRITICAL"),
    ("enumerate-iam", "enumerate-iam (permission bruteforcer)", "CRITICAL"),
    ("scoutsuite", "ScoutSuite (audit tool)", "HIGH"),
    ("prowler", "Prowler (audit tool)", "MEDIUM"),
    ("trufflehog", "TruffleHog (secret scanner)", "HIGH"),
    ("nuclei", "Nuclei", "HIGH"),
    ("python-requests", "Raw HTTP client (hand-rolled signing)", "HIGH"),
    ("curl", "curl", "HIGH"),
    ("boto3", "boto3 script", "MEDIUM"),
    ("botocore", "botocore script", "MEDIUM"),
    ("aws-cli", "AWS CLI", "MEDIUM"),
    ("terraform", "Terraform", "LOW"),
    ("mozilla", "Web browser", "HIGH"),
]

# requestParameters keys that name the resource being touched, best first.
_RESOURCE_KEYS = (
    "bucketName",
    "key",
    "secretId",
    "name",
    "roleArn",
    "roleName",
    "userName",
    "policyArn",
    "policyName",
    "functionName",
    "tableName",
    "instanceId",
    "keyId",
    "dBInstanceIdentifier",
    "logGroupName",
    "trailName",
    "groupName",
)


@dataclass
class Signal:
    """A single reason this event is interesting."""

    name: str
    detail: str
    severity: str

    def to_dict(self) -> dict:
        return {"name": self.name, "detail": self.detail, "severity": self.severity}


@dataclass
class AnalyzedEvent:
    """A :class:`CanaryEvent` enriched with classification and detection signals."""

    event: CanaryEvent
    technique: mitre.Technique
    signals: list[Signal] = field(default_factory=list)
    is_canary: bool = False
    tool: str = "Unknown client"
    target_resource: str = ""

    @property
    def severity(self) -> str:
        """Highest severity across the technique and every raised signal."""
        return mitre.highest_severity(
            [self.technique.severity] + [s.severity for s in self.signals]
        )

    @property
    def tactic(self) -> str:
        return self.technique.tactic

    def summary_line(self, include_tactic: bool = True) -> str:
        """One-line rendering used in the timeline and in Slack messages.

        Inside a timeline phase the tactic is already in the phase header, so
        callers there pass ``include_tactic=False``.
        """
        stamp = self.event.event_time.strftime("%H:%M:%S")
        target = f" -> {self.target_resource}" if self.target_resource else ""
        outcome = f" [{self.event.error_code}]" if self.event.denied else ""
        tactic = f"  ({self.tactic})" if include_tactic else ""
        return f"{stamp}  {self.event.event_name}{target}{outcome}{tactic}"

    def to_dict(self) -> dict:
        return {
            **self.event.to_dict(),
            "is_canary": self.is_canary,
            "severity": self.severity,
            "tool": self.tool,
            "target_resource": self.target_resource,
            "mitre": self.technique.to_dict(),
            "signals": [s.to_dict() for s in self.signals],
        }


def fingerprint_tool(user_agent: str) -> tuple[str, str | None]:
    """Identify the client behind a user-agent string.

    Returns ``(human_label, severity_if_suspicious)``. A severity of ``None``
    means the tool itself is not evidence of anything.
    """
    if not user_agent:
        return "Missing user-agent", "HIGH"

    lowered = user_agent.lower()
    for needle, label, severity in _TOOL_FINGERPRINTS:
        if needle in lowered:
            # Console and SDK traffic is normal for a real user; for a canary
            # identity it is still reported, just not as its own signal.
            return label, severity if severity in {"HIGH", "CRITICAL"} else None
    if "console.amazonaws.com" in lowered or "aws-internal" in lowered:
        return "AWS Console / internal", None
    return user_agent.split("/")[0] or "Unknown client", None


def extract_target(event: CanaryEvent) -> str:
    """Pull the concrete resource an action was aimed at, if we can find one."""
    params = event.request_parameters
    if not params:
        return ""

    parts: list[str] = []
    for key in _RESOURCE_KEYS:
        value = params.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
        if len(parts) == 2:
            break
    return "/".join(parts)


def _build_signals(event: CanaryEvent, is_canary: bool, tool_severity: str | None,
                   tool: str) -> list[Signal]:
    signals: list[Signal] = []

    if is_canary:
        signals.append(
            Signal(
                "canary_identity_used",
                f"{event.principal_name} is a planted deception identity with no "
                "legitimate use. Any activity is malicious by definition.",
                "CRITICAL",
            )
        )

    if tool_severity:
        signals.append(Signal("suspicious_client", tool, tool_severity))

    if event.denied:
        signals.append(
            Signal(
                "access_denied",
                f"{event.event_name} was denied ({event.error_code}) - consistent "
                "with permission enumeration against an unknown key.",
                "MEDIUM",
            )
        )

    if event.principal_type == "Root":
        signals.append(Signal("root_principal", "Call made by the account root user.", "HIGH"))

    if event.principal_type in {"IAMUser", "AssumedRole"} and not event.mfa_authenticated:
        if event.event_name in mitre.ACTION_MAP and mitre.ACTION_MAP[
            event.event_name
        ].tactic in {"Privilege Escalation", "Persistence", "Defense Evasion"}:
            signals.append(
                Signal(
                    "no_mfa_on_sensitive_action",
                    f"{event.event_name} performed without MFA.",
                    "HIGH",
                )
            )

    if event.source_ip in {"unknown", ""}:
        signals.append(Signal("missing_source_ip", "Event has no source IP.", "LOW"))

    return signals


def analyze_event(payload: dict, config: Config | None = None) -> AnalyzedEvent:
    """Analyze one EventBridge/CloudTrail payload.

    This is the single entry point used by the Lambda handler, the timeline
    engine and the CLI, so every event in the system is classified identically.
    """
    config = config or Config.from_env()
    event = CanaryEvent.from_event(payload)
    technique = mitre.classify(event.event_name, event.event_source)
    tool, tool_severity = fingerprint_tool(event.user_agent)
    is_canary = event.is_canary(config.canary_prefixes, config.canary_identities)

    return AnalyzedEvent(
        event=event,
        technique=technique,
        signals=_build_signals(event, is_canary, tool_severity, tool),
        is_canary=is_canary,
        tool=tool,
        target_resource=extract_target(event),
    )


def analyze_many(payloads: list[dict], config: Config | None = None) -> list[AnalyzedEvent]:
    """Analyze a batch of events, chronologically sorted and de-duplicated."""
    config = config or Config.from_env()
    seen: set[str] = set()
    analyzed: list[AnalyzedEvent] = []
    for payload in payloads:
        try:
            item = analyze_event(payload, config)
        except (TypeError, AttributeError):
            continue
        key = item.event.event_id or item.event.fingerprint()
        if key in seen:
            continue
        seen.add(key)
        analyzed.append(item)
    analyzed.sort(key=lambda a: a.event.event_time)
    return analyzed
