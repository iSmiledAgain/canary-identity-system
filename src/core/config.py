"""Runtime configuration for the canary detection engine.

Everything is environment-driven so the same code runs unchanged in AWS Lambda
(where Person A sets the variables in ``terraform/lambda.tf``) and locally via
``python -m src.cli``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    """Resolved configuration for one invocation of the engine."""

    # --- Deception inventory -------------------------------------------------
    # Any principal whose userName/ARN matches one of these prefixes is a trap.
    canary_prefixes: list[str] = field(
        default_factory=lambda: _env_list("CANARY_IDENTITY_PREFIXES", "canary-")
    )
    # Explicit allow-list of canary principals, if you prefer exact matching.
    canary_identities: list[str] = field(
        default_factory=lambda: _env_list("CANARY_IDENTITIES")
    )

    # --- Timeline reconstruction --------------------------------------------
    # "cloudwatch" | "athena" | "none"
    timeline_backend: str = field(
        default_factory=lambda: os.environ.get("TIMELINE_BACKEND", "cloudwatch").lower()
    )
    log_group: str = field(
        default_factory=lambda: os.environ.get("CLOUDTRAIL_LOG_GROUP", "")
    )
    athena_database: str = field(
        default_factory=lambda: os.environ.get("ATHENA_DATABASE", "")
    )
    athena_table: str = field(
        default_factory=lambda: os.environ.get("ATHENA_TABLE", "cloudtrail_logs")
    )
    athena_output_location: str = field(
        default_factory=lambda: os.environ.get("ATHENA_OUTPUT_LOCATION", "")
    )
    lookback_hours: int = field(
        default_factory=lambda: _env_int("TIMELINE_LOOKBACK_HOURS", 24)
    )
    max_timeline_events: int = field(
        default_factory=lambda: _env_int("TIMELINE_MAX_EVENTS", 200)
    )
    query_timeout_seconds: int = field(
        default_factory=lambda: _env_int("TIMELINE_QUERY_TIMEOUT", 45)
    )

    # --- Alerting ------------------------------------------------------------
    slack_webhook_url: str = field(
        default_factory=lambda: os.environ.get("SLACK_WEBHOOK_URL", "")
    )
    discord_webhook_url: str = field(
        default_factory=lambda: os.environ.get("DISCORD_WEBHOOK_URL", "")
    )
    generic_webhook_url: str = field(
        default_factory=lambda: os.environ.get("GENERIC_WEBHOOK_URL", "")
    )
    dry_run: bool = field(default_factory=lambda: _env_bool("ALERT_DRY_RUN", False))
    environment: str = field(
        default_factory=lambda: os.environ.get("DEPLOY_ENVIRONMENT", "dev")
    )

    @classmethod
    def from_env(cls) -> "Config":
        return cls()

    def has_any_alert_sink(self) -> bool:
        return bool(
            self.slack_webhook_url
            or self.discord_webhook_url
            or self.generic_webhook_url
        )
