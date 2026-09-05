"""AWS Lambda entry point for the canary detection engine.

Person A wires this up in ``terraform/lambda.tf``:

    handler = "src.handler.lambda_handler"
    runtime = "python3.12"

The function accepts a single EventBridge event (the normal path) or an SQS /
Kinesis style batch, analyses each record, and alerts on the ones that involve a
planted canary identity.
"""

from __future__ import annotations

import json
import logging

from .core.alerter import dispatch
from .core.config import Config
from .core.incident import Incident, build_incident

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _extract_records(event: dict) -> list[dict]:
    """Unwrap the batching envelopes an EventBridge target can receive."""
    if not isinstance(event, dict):
        return []

    records = event.get("Records")
    if isinstance(records, list):
        unwrapped = []
        for record in records:
            body = record.get("body") if isinstance(record, dict) else None
            if isinstance(body, str):
                try:
                    unwrapped.append(json.loads(body))
                    continue
                except json.JSONDecodeError:
                    pass
            unwrapped.append(record)
        return unwrapped

    return [event]


def process_event(payload: dict, config: Config | None = None) -> Incident:
    """Analyse one payload and alert if it is a genuine canary trigger."""
    config = config or Config.from_env()
    incident = build_incident(payload, config)

    # Structured line so the incident is queryable in CloudWatch Logs Insights.
    logger.info(json.dumps({"canary_incident": incident.to_dict()}, default=str))

    if incident.suppressed:
        logger.info("Suppressed: %s", incident.suppression_reason)
        return incident

    for result in dispatch(incident, config):
        if not result.ok:
            logger.error("Alert delivery failed on %s: %s", result.channel, result.error)
    return incident


def lambda_handler(event: dict, context=None) -> dict:  # noqa: ARG001 - AWS signature
    config = Config.from_env()
    records = _extract_records(event)

    processed: list[dict] = []
    for payload in records:
        try:
            incident = process_event(payload, config)
        except Exception as exc:  # noqa: BLE001 - one bad record must not drop the batch
            logger.exception("Failed to process record: %s", exc)
            processed.append({"error": f"{type(exc).__name__}: {exc}"})
            continue
        processed.append(
            {
                "incident_id": incident.incident_id,
                "severity": incident.severity,
                "risk_score": incident.profile.risk_score,
                "suppressed": incident.suppressed,
                "principal": incident.trigger.event.principal_name,
                "chain": incident.timeline.chain,
            }
        )

    alerted = [p for p in processed if not p.get("suppressed") and "error" not in p]
    return {
        "statusCode": 200,
        "received": len(records),
        "alerted": len(alerted),
        "incidents": processed,
    }
