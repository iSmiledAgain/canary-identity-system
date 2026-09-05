"""Stage 2: profile the *behaviour* behind a set of events.

A single API call tells you what happened. The profiler looks at the whole
burst and answers the questions an incident responder actually asks: is this a
human at a keyboard or a script? Are they just validating a stolen key, or
sweeping for permissions? How far along the kill chain did they get?
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from . import mitre
from .analyzer import AnalyzedEvent

# Thresholds. Kept as module constants so they are easy to tune and to cite in
# the README when explaining detection logic.
AUTOMATION_MIN_EVENTS = 4
AUTOMATION_JITTER_SECONDS = 1.5
BURST_EVENTS_PER_MINUTE = 10.0
ENUMERATION_DENIED_RATIO = 0.6
ENUMERATION_MIN_EVENTS = 5


@dataclass
class ActorProfile:
    """Behavioural summary of one actor's session against the deception estate."""

    principals: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)

    event_count: int = 0
    denied_count: int = 0
    denied_ratio: float = 0.0
    duration_seconds: float = 0.0
    events_per_minute: float = 0.0
    median_interval_seconds: float = 0.0
    interval_jitter_seconds: float = 0.0

    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)

    automated: bool = False
    behaviour: str = "Unclassified activity"
    max_severity: str = "INFO"
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "principals": self.principals,
            "source_ips": self.source_ips,
            "user_agents": self.user_agents,
            "tools": self.tools,
            "regions": self.regions,
            "event_count": self.event_count,
            "denied_count": self.denied_count,
            "denied_ratio": round(self.denied_ratio, 3),
            "duration_seconds": round(self.duration_seconds, 1),
            "events_per_minute": round(self.events_per_minute, 2),
            "median_interval_seconds": round(self.median_interval_seconds, 2),
            "interval_jitter_seconds": round(self.interval_jitter_seconds, 2),
            "tactics": self.tactics,
            "techniques": self.techniques,
            "targets": self.targets,
            "automated": self.automated,
            "behaviour": self.behaviour,
            "max_severity": self.max_severity,
            "risk_score": self.risk_score,
            "risk_reasons": self.risk_reasons,
        }


def _unique(values: list[str]) -> list[str]:
    """Order-preserving de-duplication, dropping empties."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _intervals(events: list[AnalyzedEvent]) -> list[float]:
    stamps = sorted(e.event.event_time for e in events)
    return [
        (later - earlier).total_seconds()
        for earlier, later in zip(stamps, stamps[1:])
    ]


def _describe_behaviour(profile: ActorProfile, tactics: list[str]) -> str:
    """Map the shape of the session onto a plain-English label."""
    tactic_set = set(tactics)

    if "Exfiltration" in tactic_set or "Impact" in tactic_set:
        return "Data exfiltration / destructive activity"
    if "Defense Evasion" in tactic_set:
        return "Anti-forensics - attempting to blind logging"
    if "Persistence" in tactic_set:
        return "Persistence establishment (new credentials or principals)"
    if "Privilege Escalation" in tactic_set:
        return "Privilege escalation attempt"
    if "Credential Access" in tactic_set:
        return "Secret harvesting"
    if (
        profile.denied_ratio >= ENUMERATION_DENIED_RATIO
        and profile.event_count >= ENUMERATION_MIN_EVENTS
    ):
        return "Permission enumeration / brute-force API sweep"
    if profile.event_count <= 2 and tactic_set <= {"Discovery", "Unclassified"}:
        return "Credential validation (attacker testing a found key)"
    if "Discovery" in tactic_set:
        return "Hands-on reconnaissance of the account"
    return "Unclassified activity"


def _score_risk(profile: ActorProfile, events: list[AnalyzedEvent]) -> tuple[int, list[str]]:
    """Additive 0-100 risk score. Every point added carries a stated reason."""
    score = 0
    reasons: list[str] = []

    if any(e.is_canary for e in events):
        score += 50
        reasons.append("Canary identity used - zero legitimate use, confirmed compromise (+50)")

    severity_points = {"INFO": 0, "LOW": 3, "MEDIUM": 8, "HIGH": 15, "CRITICAL": 25}
    points = severity_points.get(profile.max_severity, 0)
    if points:
        score += points
        reasons.append(f"Peak event severity {profile.max_severity} (+{points})")

    advanced = [
        t for t in profile.tactics
        if mitre.tactic_rank(t) >= mitre.TACTIC_ORDER.index("Privilege Escalation")
        and t in mitre.TACTIC_ORDER
    ]
    if advanced:
        score += 15
        reasons.append(f"Reached late-stage tactics: {', '.join(advanced)} (+15)")

    if len(set(profile.tactics) & set(mitre.TACTIC_ORDER)) >= 3:
        score += 10
        reasons.append("Activity spans three or more ATT&CK tactics (+10)")

    if profile.automated:
        score += 8
        reasons.append(
            f"Machine-speed, low-jitter call pattern "
            f"(median {profile.median_interval_seconds:.1f}s apart) (+8)"
        )

    if profile.events_per_minute >= BURST_EVENTS_PER_MINUTE:
        score += 7
        reasons.append(f"High call velocity: {profile.events_per_minute:.1f} calls/min (+7)")

    if (
        profile.denied_ratio >= ENUMERATION_DENIED_RATIO
        and profile.event_count >= ENUMERATION_MIN_EVENTS
    ):
        score += 7
        reasons.append(f"{profile.denied_ratio:.0%} of calls denied - permission sweep (+7)")

    if len(profile.source_ips) > 1:
        score += 5
        reasons.append(f"Credential used from {len(profile.source_ips)} distinct IPs (+5)")

    return min(score, 100), reasons


def profile_actor(events: list[AnalyzedEvent]) -> ActorProfile:
    """Build an :class:`ActorProfile` from a chronological list of events."""
    profile = ActorProfile()
    if not events:
        return profile

    ordered = sorted(events, key=lambda e: e.event.event_time)
    profile.event_count = len(ordered)
    profile.principals = _unique([e.event.principal_id for e in ordered])
    profile.source_ips = _unique([e.event.source_ip for e in ordered])
    profile.user_agents = _unique([e.event.user_agent for e in ordered])
    profile.tools = _unique([e.tool for e in ordered])
    profile.regions = _unique([e.event.aws_region for e in ordered])
    profile.targets = _unique([e.target_resource for e in ordered])[:10]

    profile.denied_count = sum(1 for e in ordered if e.event.denied)
    profile.denied_ratio = profile.denied_count / profile.event_count

    span = (ordered[-1].event.event_time - ordered[0].event.event_time).total_seconds()
    profile.duration_seconds = span
    profile.events_per_minute = (
        profile.event_count / (span / 60) if span > 0 else float(profile.event_count)
    )

    gaps = _intervals(ordered)
    if gaps:
        profile.median_interval_seconds = statistics.median(gaps)
        profile.interval_jitter_seconds = (
            statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
        )
        # Scripted tooling fires at a near-constant cadence; a human does not.
        profile.automated = (
            profile.event_count >= AUTOMATION_MIN_EVENTS
            and profile.interval_jitter_seconds <= AUTOMATION_JITTER_SECONDS
        )

    tactics = [e.tactic for e in ordered]
    profile.tactics = sorted(_unique(tactics), key=mitre.tactic_rank)
    profile.techniques = _unique([e.technique.label for e in ordered])
    profile.max_severity = mitre.highest_severity([e.severity for e in ordered])

    profile.behaviour = _describe_behaviour(profile, tactics)
    profile.risk_score, profile.risk_reasons = _score_risk(profile, ordered)
    return profile
