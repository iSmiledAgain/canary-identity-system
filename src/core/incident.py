"""The object that ties the four stages together.

An :class:`Incident` is what the Lambda handler produces and what the alerter
renders: one canary trigger, the correlated timeline around it, and the
behavioural profile of the actor who caused it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .analyzer import AnalyzedEvent, analyze_event
from .config import Config
from .profiler import ActorProfile, profile_actor
from .timeline import LogSource, Timeline, reconstruct


@dataclass
class Incident:
    incident_id: str
    detected_at: datetime
    trigger: AnalyzedEvent
    timeline: Timeline
    profile: ActorProfile
    environment: str = "dev"
    suppressed: bool = False
    suppression_reason: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        from . import mitre

        return mitre.highest_severity([self.trigger.severity, self.profile.max_severity])

    @property
    def title(self) -> str:
        return (
            f"CANARY IDENTITY TRIGGERED - {self.trigger.event.principal_name}"
            if self.trigger.is_canary
            else f"Suspicious IAM activity - {self.trigger.event.principal_name}"
        )

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "detected_at": self.detected_at.isoformat().replace("+00:00", "Z"),
            "environment": self.environment,
            "title": self.title,
            "severity": self.severity,
            "risk_score": self.profile.risk_score,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "tags": self.tags,
            "trigger": self.trigger.to_dict(),
            "profile": self.profile.to_dict(),
            "timeline": self.timeline.to_dict(),
        }


def build_incident(
    payload: dict,
    config: Config | None = None,
    source: LogSource | None = None,
) -> Incident:
    """Run the full pipeline - analyze, correlate, profile - on one event.

    Events from principals that are not canaries are still processed but marked
    ``suppressed`` so the handler can drop them without an alert. That keeps the
    zero-false-positive promise while leaving the analysis visible in the logs.
    """
    config = config or Config.from_env()
    trigger = analyze_event(payload, config)
    timeline = reconstruct(trigger, config, source)
    profile = profile_actor(timeline.events)

    incident = Incident(
        incident_id=f"CAN-{uuid.uuid4().hex[:10].upper()}",
        detected_at=datetime.now(tz=timezone.utc),
        trigger=trigger,
        timeline=timeline,
        profile=profile,
        environment=config.environment,
        tags=sorted({t for t in profile.tactics}),
    )

    if not trigger.is_canary:
        incident.suppressed = True
        incident.suppression_reason = (
            f"{trigger.event.principal_name} is not a registered canary identity "
            f"(prefixes: {', '.join(config.canary_prefixes) or 'none'})."
        )
    return incident
