"""Stage 4: turn an incident into something a human sees within seconds.

Formatters are pure functions returning plain dictionaries, so they are fully
unit-testable without a network. :func:`dispatch` is the only function that
performs I/O, and it degrades gracefully: a failing webhook is reported in the
result rather than raised, because losing the alert is worse than losing one
delivery channel.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import Config
from .incident import Incident

SEVERITY_EMOJI = {
    "INFO": ":information_source:",
    "LOW": ":large_blue_circle:",
    "MEDIUM": ":large_orange_diamond:",
    "HIGH": ":rotating_light:",
    "CRITICAL": ":fire:",
}

# Discord embed colours (decimal RGB).
SEVERITY_COLOR = {
    "INFO": 0x3498DB,
    "LOW": 0x2ECC71,
    "MEDIUM": 0xF1C40F,
    "HIGH": 0xE67E22,
    "CRITICAL": 0xE74C3C,
}

MAX_TIMELINE_LINES = 25


@dataclass
class DeliveryResult:
    channel: str
    ok: bool
    status: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "ok": self.ok,
            "status": self.status,
            "error": self.error,
        }


def _truncate_chain(text: str, max_lines: int = MAX_TIMELINE_LINES) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    hidden = len(lines) - max_lines
    return "\n".join(lines[:max_lines] + [f"... (+{hidden} more lines)"])


def _headline_fields(incident: Incident) -> list[tuple[str, str]]:
    event = incident.trigger.event
    return [
        ("Identity", event.principal_name),
        ("Access Key", event.access_key_id or "n/a"),
        ("Source IP", event.source_ip),
        ("Region", event.aws_region or "n/a"),
        ("Action", event.event_name),
        ("Outcome", event.error_code or "Allowed"),
        ("Client", incident.trigger.tool),
        ("Risk Score", f"{incident.profile.risk_score}/100"),
    ]


# --------------------------------------------------------------------------- #
# Formatters
# --------------------------------------------------------------------------- #
def build_slack_payload(incident: Incident) -> dict:
    """Slack Block Kit message."""
    emoji = SEVERITY_EMOJI.get(incident.severity, ":warning:")
    trigger = incident.trigger
    chain = " -> ".join(incident.timeline.chain) or "n/a"

    fields = [
        {"type": "mrkdwn", "text": f"*{label}*\n`{value}`"}
        for label, value in _headline_fields(incident)
    ]

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{incident.severity}: {incident.title}"[:150]},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} `{incident.incident_id}` | env `{incident.environment}` | "
                        f"{incident.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    ),
                }
            ],
        },
        {"type": "section", "fields": fields[:10]},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*MITRE ATT&CK*\n{trigger.tactic} - {trigger.technique.label}\n"
                    f"*Behaviour*\n{incident.profile.behaviour}"
                ),
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Attack chain*\n`{chain}`"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Reconstructed timeline*\n```"
                + _truncate_chain(incident.timeline.render_ascii())
                + "```",
            },
        },
    ]

    if incident.profile.risk_reasons:
        reasons = "\n".join(f"- {r}" for r in incident.profile.risk_reasons)
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Why this scored {incident.profile.risk_score}*\n{reasons}"},
            }
        )

    return {
        "text": f"{emoji} {incident.severity}: {incident.title}",
        "blocks": blocks,
    }


def build_discord_payload(incident: Incident) -> dict:
    """Discord embed message."""
    chain = " -> ".join(incident.timeline.chain) or "n/a"
    fields = [
        {"name": label, "value": f"`{value}`", "inline": True}
        for label, value in _headline_fields(incident)
    ]
    fields.append(
        {
            "name": "MITRE ATT&CK",
            "value": f"{incident.trigger.tactic} - {incident.trigger.technique.label}",
            "inline": False,
        }
    )
    fields.append({"name": "Behaviour", "value": incident.profile.behaviour, "inline": False})
    fields.append({"name": "Attack chain", "value": f"`{chain}`", "inline": False})
    fields.append(
        {
            "name": "Reconstructed timeline",
            "value": "```" + _truncate_chain(incident.timeline.render_ascii(), 15)[:1000] + "```",
            "inline": False,
        }
    )

    return {
        "username": "Canary Identity System",
        "embeds": [
            {
                "title": f"{incident.severity}: {incident.title}"[:250],
                "description": f"Incident `{incident.incident_id}` in `{incident.environment}`",
                "color": SEVERITY_COLOR.get(incident.severity, 0x95A5A6),
                "fields": fields[:25],
                "timestamp": incident.detected_at.isoformat(),
                "footer": {"text": f"Risk {incident.profile.risk_score}/100"},
            }
        ],
    }


def build_generic_payload(incident: Incident) -> dict:
    """Full structured JSON, for a SIEM or a custom dashboard."""
    return incident.to_dict()


def render_console(incident: Incident) -> str:
    """Plain-text rendering for local runs and CloudWatch Logs."""
    lines = [
        "=" * 72,
        f"  {incident.severity}  {incident.title}",
        f"  {incident.incident_id} | env={incident.environment} | "
        f"risk={incident.profile.risk_score}/100",
        "=" * 72,
    ]
    for label, value in _headline_fields(incident):
        lines.append(f"  {label:<12} {value}")
    lines += [
        "",
        f"  MITRE       {incident.trigger.tactic} - {incident.trigger.technique.label}",
        f"  Behaviour   {incident.profile.behaviour}",
        f"  Automated   {incident.profile.automated}",
        f"  Chain       {' -> '.join(incident.timeline.chain) or 'n/a'}",
        "",
        "  RECONSTRUCTED TIMELINE",
        "  " + "-" * 68,
    ]
    lines += ["  " + line for line in incident.timeline.render_ascii().splitlines()]
    if incident.profile.risk_reasons:
        lines += ["", "  RISK SCORING", "  " + "-" * 68]
        lines += [f"  - {reason}" for reason in incident.profile.risk_reasons]
    if incident.timeline.note:
        lines += ["", f"  NOTE: {incident.timeline.note}"]
    lines.append("=" * 72)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Delivery
# --------------------------------------------------------------------------- #
def post_json(url: str, payload: dict, timeout: int = 10) -> DeliveryResult:
    """POST a JSON body using only the standard library.

    Lambda's Python runtime does not bundle ``requests``; using ``urllib`` keeps
    the deployment package dependency-free for Person A.
    """
    channel = "webhook"
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "canary-identity-system/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return DeliveryResult(channel, 200 <= response.status < 300, response.status)
    except urllib.error.HTTPError as exc:
        return DeliveryResult(channel, False, exc.code, exc.reason or "HTTPError")
    except Exception as exc:  # noqa: BLE001 - a dead sink must not kill the handler
        return DeliveryResult(channel, False, 0, f"{type(exc).__name__}: {exc}")


def dispatch(incident: Incident, config: Config | None = None) -> list[DeliveryResult]:
    """Send the incident to every configured sink.

    In dry-run mode (or with no sinks configured) the alert is printed instead,
    which is what the CLI and the pytest suite rely on.
    """
    config = config or Config.from_env()
    results: list[DeliveryResult] = []

    targets = [
        ("slack", config.slack_webhook_url, build_slack_payload),
        ("discord", config.discord_webhook_url, build_discord_payload),
        ("webhook", config.generic_webhook_url, build_generic_payload),
    ]

    if config.dry_run or not config.has_any_alert_sink():
        print(render_console(incident))
        return [DeliveryResult("console", True, 0, "")]

    for channel, url, builder in targets:
        if not url:
            continue
        result = post_json(url, builder(incident))
        result.channel = channel
        results.append(result)
    return results
