# Canary Identity System

A cloud identity **deception** system. It plants realistic-but-fake AWS
credentials where an attacker would find them, and when one is used it detects
the use, classifies it against MITRE ATT&CK, profiles the attacker's behaviour,
reconstructs the attack timeline, and alerts - in seconds.

Because a canary identity has **no legitimate use**, any activity involving one
is malicious by definition. That is what makes this a zero-false-positive
detection rather than another anomaly-scoring tool.

```
[ Plant canary creds ] --> [ Attacker finds and uses them ]
                                        |
                                        v
                            [ CloudTrail management events ]
                                        |
                                        v
                            [ EventBridge rule (canary ARNs) ]
                                        |
                                        v
                            [ Lambda: detection engine ]
              ______________________________|______________________________
             |                    |                    |                   |
        [ Analyze ]         [ Correlate ]         [ Profile ]         [ Alert ]
      MITRE ATT&CK        24h timeline from      risk score,      Slack / Discord
      classification      IP + key + ARN         automation,       / JSON / SIEM
                          pivots                 behaviour
```

## What an alert looks like

```
========================================================================
  CRITICAL  CANARY IDENTITY TRIGGERED - canary-prod-db-backup
  CAN-958E9BDCB7 | env=prod | risk=100/100
========================================================================
  Identity     canary-prod-db-backup
  Access Key   AKIAIOSFODNN7CANARY
  Source IP    198.51.100.42
  Action       StopLogging
  Outcome      AccessDenied
  Client       boto3 script

  MITRE       Defense Evasion - T1562.008 - Impair Defenses: Disable or Modify Cloud Logs
  Behaviour   Anti-forensics - attempting to blind logging
  Automated   True
  Chain       Discovery -> Credential Access -> Privilege Escalation -> Persistence
              -> Collection -> Defense Evasion

  RECONSTRUCTED TIMELINE
  ----------------------------------------------------------------------
  03:14:10  Discovery
            - 03:14:10  GetCallerIdentity
            - 03:14:22  ListBuckets [AccessDenied]
            - 03:14:34  ListAttachedUserPolicies -> canary-prod-db-backup [AccessDenied]
               |
               v
  03:14:58  Credential Access
            - 03:14:58  GetSecretValue -> prod/db/master-password [AccessDenied]
               |
               v
  03:15:11  Privilege Escalation
            - 03:15:11  AssumeRole -> arn:aws:iam::...:role/prod-admin-role [AccessDenied]
               ...

  RISK SCORING
  ----------------------------------------------------------------------
  - Canary identity used - zero legitimate use, confirmed compromise (+50)
  - Peak event severity CRITICAL (+25)
  - Reached late-stage tactics: Privilege Escalation, Persistence (+15)
  - Activity spans three or more ATT&CK tactics (+10)
  - Machine-speed, low-jitter call pattern (median 12.0s apart) (+8)
  - 89% of calls denied - permission sweep (+7)
========================================================================
```

Reproduce it yourself, with no AWS account:

```bash
python -m src.cli demo
```

## Try it in 30 seconds

```bash
git clone https://github.com/iSmiledAgain/canary-identity-system.git
cd canary-identity-system
python3 -m pip install -r requirements-dev.txt

make demo    # replay a 9-step simulated intrusion through the full pipeline
make test    # 118 tests, no AWS account and no network required
make cov     # coverage report
```

## Repository layout

```
terraform/                 IaC: canary identities, CloudTrail, EventBridge, Lambda   [Person A]
  canary_iam.tf              decoy IAM users/roles with explicit-deny boundaries
  eventbridge.tf             rule filtering CloudTrail for canary principals
  lambda.tf                  detection function + invoke permission
scripts/
  seed_honeytokens.py      plants canary keys into decoy locations                   [Person A]
src/
  handler.py               Lambda entry point (src.handler.lambda_handler)           [Person B]
  cli.py                   offline replay/demo driver                                [Person B]
  core/
    models.py                CanaryEvent - one normalised event shape
    mitre.py                 AWS API action -> ATT&CK tactic/technique
    analyzer.py              classification, tool fingerprinting, signals
    timeline.py              log correlation + kill-chain assembly
    profiler.py              behavioural profiling + risk scoring
    alerter.py               Slack / Discord / JSON / console formatters
    incident.py              composes the pipeline into one Incident
    config.py                environment-driven configuration
tests/                     118 unit tests + fixtures                                 [Person B]
docs/
  detection-engine.md      how the detection logic works and why
  integration-contract.md  the interface between src/ and terraform/
```

## How the detection works

Four stages, each independently testable:

1. **Analyze** (`analyzer.py`) - normalise the CloudTrail record, map the API
   action to an ATT&CK technique, fingerprint the client from its user-agent
   (Pacu, CloudFox, raw `curl`, browser, SDK), extract the target resource, and
   raise detection signals. Severity is the maximum of the technique's own
   severity and every signal raised.

2. **Correlate** (`timeline.py`) - pivot on source IP **and** access key **and**
   principal ARN, query the last 24 hours of CloudTrail through CloudWatch Logs
   Insights or Athena, and fold the results into contiguous kill-chain phases.
   Pivoting on all three catches both a credential moving between hosts and an
   attacker escalating into a different role.

3. **Profile** (`profiler.py`) - measure call velocity, inter-event jitter
   (scripted tooling has a near-constant cadence; humans do not), the
   `AccessDenied` ratio (a permission sweep is mostly denials), tactic coverage
   and IP spread. Produces a behaviour label and a 0-100 risk score in which
   **every point carries a stated reason**.

4. **Alert** (`alerter.py`) - render to Slack Block Kit, a Discord embed, generic
   JSON for a SIEM, or the console. Formatters are pure functions; only
   `dispatch()` touches the network, and a dead sink is reported rather than
   raised.

Full rationale in [docs/detection-engine.md](docs/detection-engine.md).

## Design decisions

- **Zero runtime dependencies.** The engine uses only the standard library
  (`urllib` for webhooks, `statistics` for profiling). `src/` zips directly into
  a Lambda package - no vendoring, no layer, no cold-start penalty. `boto3` is
  imported lazily and only when a log backend is actually queried, so the test
  suite needs neither AWS credentials nor the SDK.
- **Fail open, never silent.** A timed-out log query, an unreachable webhook or a
  malformed record is recorded in the output and the alert still fires with what
  is known. Losing an alert is worse than losing an enrichment.
- **Suppression instead of filtering.** Non-canary events are still analysed and
  logged, just marked `suppressed`. The EventBridge rule can be over-broad
  without producing false alerts.
- **Attacker-controlled input is untrusted.** Source IPs and ARNs end up inside
  log queries, so pivot values are sanitised before query construction
  (`tests/test_timeline.py` asserts this).

## Deployment

See [docs/integration-contract.md](docs/integration-contract.md) for the Lambda
handler path, required IAM permissions, environment variables, accepted input
shapes and the canary-naming requirement.

```bash
make package                  # -> lambda_payload.zip (handler: src.handler.lambda_handler)
cd terraform && terraform init && terraform apply
```

<!-- Person A: infrastructure setup steps (terraform vars, CloudTrail prerequisites,
     seeding the honeytokens) go here. -->

## Validation

End-to-end red/blue test once both halves are deployed:

```bash
# Red team - use the planted credential
aws sts get-caller-identity --profile canary
aws s3 ls --profile canary

# Blue team - watch the detection fire
aws logs tail /aws/lambda/canary-identity-detector --follow
```

## Cost

Everything runs inside the AWS Always Free tier: CloudTrail management events
(first copy free), EventBridge (1M events/month), Lambda (1M requests/month),
CloudWatch Logs (5 GB/month), IAM (always free). Set a $1 zero-spend budget
alert and keep CloudTrail on **management events only** - data events bill per
object.

## Team

| | Scope |
| --- | --- |
| **Person A** | Terraform, canary IAM identities and deny boundaries, CloudTrail + EventBridge ingestion, Lambda provisioning, honeytoken seeding. |
| **Person B** | Detection engine, ATT&CK mapping, timeline reconstruction, behavioural profiling, alerting, test suite. |
