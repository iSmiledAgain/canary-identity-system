# Detection Engine (Person B)

The engine turns one CloudTrail record into a triaged incident. It is a pure
Python package with **no third-party runtime dependencies**, so it can be zipped
straight into a Lambda deployment package.

## Pipeline

```
EventBridge event
      |
      v
[1] analyzer.py    parse + normalise + classify (MITRE ATT&CK) + raise signals
      |
      v
[2] timeline.py    pivot on IP / access key / ARN, query log history,
                   fold correlated events into ordered kill-chain phases
      |
      v
[3] profiler.py    behavioural profile over the whole session,
                   0-100 risk score with a stated reason per point
      |
      v
[4] alerter.py     Slack Block Kit / Discord embed / generic JSON / console
```

`incident.py` composes the four stages into one `Incident`; `handler.py` is the
Lambda entry point; `cli.py` runs the same pipeline offline.

## Modules

| File | Responsibility |
| --- | --- |
| `src/core/models.py` | `CanaryEvent` - normalises EventBridge envelopes, bare CloudTrail records and flattened Logs Insights rows into one shape. |
| `src/core/mitre.py` | 100+ AWS API actions mapped to ATT&CK tactics/techniques, plus verb-based fallbacks so unseen actions still classify. |
| `src/core/analyzer.py` | Classification, tool fingerprinting, target-resource extraction, detection signals, severity escalation. |
| `src/core/timeline.py` | Three log backends behind one interface + kill-chain phase assembly. |
| `src/core/profiler.py` | Automation detection, velocity, enumeration ratio, behaviour label, risk scoring. |
| `src/core/alerter.py` | Pure formatters + `urllib`-based delivery. |
| `src/core/incident.py` | The `Incident` object and the suppression rule. |
| `src/handler.py` | Lambda handler, batch unwrapping, structured logging. |
| `src/cli.py` | `replay` / `demo` commands for offline work. |

## Detection logic worth explaining in an interview

**Zero false positives by construction.** A canary identity has no legitimate
use, so any activity is malicious by definition. `Incident.suppressed` marks
events from non-canary principals: they are still analysed and logged, but never
alerted on. That is the whole premise of deception engineering.

**Severity is the max of the technique and every signal.** `ListBuckets` is a
`MEDIUM` discovery action on its own, but a `ListBuckets` from a canary identity
via `curl` is `CRITICAL`. See `AnalyzedEvent.severity`.

**Automation detection uses jitter, not rate.** A script calls at a near-constant
cadence; a human does not. `profiler.py` flags a session as automated when the
population standard deviation of inter-event gaps is under
`AUTOMATION_JITTER_SECONDS` (1.5s) across at least 4 events. A fast human still
scores as manual, and a slow script still scores as automated.

**Enumeration is a denial-ratio signal.** An attacker with an unknown key sprays
API calls to discover permissions. A session with >= 60% `AccessDenied` across
>= 5 calls is labelled a permission sweep - the *denials* are the detection, not
the successes.

**The timeline pivots on three keys, not just the IP.** Source IP alone misses a
credential that moves between hosts; the access key alone misses an attacker who
escalates into a different role. `reconstruct()` queries on
`sourceIPAddress OR accessKeyId OR arn` and merges the results.

**Every risk point carries a reason.** `ActorProfile.risk_reasons` explains the
score line by line, so an analyst can audit the verdict instead of trusting a
number.

**Failures degrade, never drop.** A dead log backend, a timed-out query or a
broken webhook is recorded in the output; the alert still fires with whatever is
known. Losing an alert is worse than losing an enrichment.

## Configuration

All configuration is environment-driven (`src/core/config.py`).

| Variable | Default | Purpose |
| --- | --- | --- |
| `CANARY_IDENTITY_PREFIXES` | `canary-` | Comma-separated name prefixes that mark a principal as a trap. |
| `CANARY_IDENTITIES` | *(empty)* | Optional exact-match allow-list of canary principals. |
| `TIMELINE_BACKEND` | `cloudwatch` | `cloudwatch`, `athena` or `none`. |
| `CLOUDTRAIL_LOG_GROUP` | *(empty)* | Log group for CloudWatch Logs Insights. |
| `ATHENA_DATABASE` / `ATHENA_TABLE` / `ATHENA_OUTPUT_LOCATION` | - / `cloudtrail_logs` / - | Athena backend settings. |
| `TIMELINE_LOOKBACK_HOURS` | `24` | How far back to correlate. |
| `TIMELINE_MAX_EVENTS` | `200` | Result cap per query. |
| `TIMELINE_QUERY_TIMEOUT` | `45` | Seconds before a log query is abandoned. |
| `SLACK_WEBHOOK_URL` | *(empty)* | Slack incoming webhook. |
| `DISCORD_WEBHOOK_URL` | *(empty)* | Discord webhook. |
| `GENERIC_WEBHOOK_URL` | *(empty)* | Any JSON sink (SIEM, dashboard). |
| `ALERT_DRY_RUN` | `false` | Print the alert instead of sending it. |
| `DEPLOY_ENVIRONMENT` | `dev` | Tag shown in alerts. |

## Local workflow

```bash
python3 -m pip install -r requirements-dev.txt
make test          # 118 tests, no AWS account or network needed
make cov           # coverage report
make demo          # replay the bundled 9-step attack fixture
```

Replay any event file through the engine:

```bash
python -m src.cli replay tests/mock_cloudtrail_event.json
python -m src.cli replay tests/fixtures/attack_sequence.json --output slack
python -m src.cli demo --json
```

## Extending the ATT&CK map

Add an entry to `ACTION_MAP` in `src/core/mitre.py`:

```python
"CreateLoginProfile": PERSISTENCE_ACCOUNT,
```

`tests/test_mitre.py` asserts that every mapped technique has a valid severity
and a known tactic, so a malformed entry fails CI.
