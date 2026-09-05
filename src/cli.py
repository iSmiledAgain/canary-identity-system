"""Local driver for the detection engine - no AWS account required.

    python -m src.cli demo
    python -m src.cli replay tests/fixtures/attack_sequence.json
    python -m src.cli replay tests/mock_cloudtrail_event.json --json

``replay`` accepts either a single CloudTrail/EventBridge event or a JSON list
of them. When given a list, the events are used both as the trigger and as the
historical log store, so the timeline engine runs end to end offline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.alerter import build_discord_payload, build_slack_payload, render_console
from .core.config import Config
from .core.incident import build_incident
from .core.timeline import StaticLogSource

DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "attack_sequence.json"


def _load(path: Path) -> list[dict]:
    with path.open() as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise SystemExit(f"{path}: expected a JSON object or list of objects")


def _pick_trigger(records: list[dict], config: Config) -> dict:
    """The trigger is the last canary event, or simply the last event."""
    from .core.analyzer import analyze_event

    canary = [
        record
        for record in records
        if analyze_event(record, config).is_canary
    ]
    return (canary or records)[-1]


def run_replay(path: Path, as_json: bool, output: str) -> int:
    config = Config.from_env()
    records = _load(path)
    if not records:
        raise SystemExit(f"{path}: no events found")

    incident = build_incident(
        _pick_trigger(records, config),
        config,
        source=StaticLogSource(records),
    )

    if as_json:
        print(json.dumps(incident.to_dict(), indent=2, default=str))
    elif output == "slack":
        print(json.dumps(build_slack_payload(incident), indent=2))
    elif output == "discord":
        print(json.dumps(build_discord_payload(incident), indent=2))
    else:
        print(render_console(incident))

    if incident.suppressed:
        print(f"\n[suppressed] {incident.suppression_reason}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="canary", description="Canary Identity System - local detection engine"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay", help="Analyse events from a JSON file")
    replay.add_argument("path", type=Path)
    replay.add_argument("--json", action="store_true", help="Emit the full incident JSON")
    replay.add_argument(
        "--output",
        choices=["console", "slack", "discord"],
        default="console",
        help="Rendering to print (ignored with --json)",
    )

    demo = sub.add_parser("demo", help="Replay the bundled five-stage attack fixture")
    demo.add_argument("--json", action="store_true")
    demo.add_argument("--output", choices=["console", "slack", "discord"], default="console")

    args = parser.parse_args(argv)
    path = DEFAULT_FIXTURE if args.command == "demo" else args.path
    return run_replay(path, args.json, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
