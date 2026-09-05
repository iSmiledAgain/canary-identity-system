# Integration Contract: Detection Engine <-> Infrastructure

Everything Person A needs in order to wire `src/` into the Terraform stack.
Nothing here requires reading the Python.

## 1. Lambda function

```hcl
resource "aws_lambda_function" "canary_detector" {
  function_name = "canary-identity-detector"
  runtime       = "python3.12"
  handler       = "src.handler.lambda_handler"   # <-- entry point
  filename      = "${path.module}/../lambda_payload.zip"
  timeout       = 60                             # >= TIMELINE_QUERY_TIMEOUT + 15
  memory_size   = 256
  role          = aws_iam_role.canary_detector.arn

  environment {
    variables = {
      CANARY_IDENTITY_PREFIXES = "canary-"
      TIMELINE_BACKEND         = "cloudwatch"
      CLOUDTRAIL_LOG_GROUP     = aws_cloudwatch_log_group.cloudtrail.name
      TIMELINE_LOOKBACK_HOURS  = "24"
      TIMELINE_QUERY_TIMEOUT   = "45"
      SLACK_WEBHOOK_URL        = var.slack_webhook_url
      DEPLOY_ENVIRONMENT       = "dev"
    }
  }
}
```

Build the zip with `make package` (produces `lambda_payload.zip` containing
`src/`). The engine has **no third-party dependencies**, so there is no `pip
install -t` vendoring step and no Lambda layer to manage.

## 2. IAM permissions the Lambda execution role needs

Beyond `AWSLambdaBasicExecutionRole`:

```hcl
# For TIMELINE_BACKEND = "cloudwatch"
statement {
  actions   = ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"]
  resources = ["*"]
}

# For TIMELINE_BACKEND = "athena" instead
statement {
  actions = [
    "athena:StartQueryExecution",
    "athena:GetQueryExecution",
    "athena:GetQueryResults",
    "glue:GetTable", "glue:GetDatabase",
    "s3:GetObject", "s3:ListBucket", "s3:PutObject",  # results bucket
  ]
  resources = ["*"]
}
```

Set `TIMELINE_BACKEND = "none"` to deploy without either; the engine still
alerts, using the trigger event alone.

## 3. Input the engine accepts

The handler accepts, in this order of preference:

1. A raw EventBridge event - `{"detail": {...CloudTrail record...}}`. **This is
   the normal path**; point the EventBridge rule target straight at the Lambda.
2. A bare CloudTrail record (no envelope).
3. A batch - `{"Records": [{"body": "<json string>"}, ...]}` - if you put SQS
   between EventBridge and Lambda.

`tests/mock_cloudtrail_event.json` is the canonical contract sample and is
asserted against in the test suite. If the EventBridge rule reshapes the event
(an input transformer, for instance), tell me before deploying - that changes
the contract.

## 4. Naming requirement for canary identities

The engine decides whether a principal is a trap by prefix match against
`CANARY_IDENTITY_PREFIXES`. Every canary IAM user/role created in
`terraform/canary_iam.tf` must therefore be named with a shared prefix:

```
canary-prod-db-backup
canary-ci-deployer
canary-s3-backup-role
```

If you prefer names with no shared prefix (better deception, since `canary-` is
a giveaway to a careful attacker), pass the full list instead:

```hcl
CANARY_IDENTITIES = join(",", [
  aws_iam_user.prod_db_backup.name,
  aws_iam_user.ci_deployer.name,
])
CANARY_IDENTITY_PREFIXES = ""
```

Both mechanisms are supported and can be combined.

## 5. EventBridge rule

The rule should match on the canary principals. Matching on `userName` only
catches IAM users; add `arn` matching to catch assumed roles:

```hcl
event_pattern = jsonencode({
  "detail-type" = ["AWS API Call via CloudTrail"]
  "detail" = {
    "userIdentity" = {
      "userName" = ["canary-prod-db-backup", "canary-ci-deployer"]
    }
  }
})
```

The engine re-checks the identity itself and suppresses anything that is not a
canary, so a slightly over-broad rule is safe - it costs a Lambda invocation,
not a false alert.

## 6. Output

The handler returns:

```json
{
  "statusCode": 200,
  "received": 1,
  "alerted": 1,
  "incidents": [
    {
      "incident_id": "CAN-958E9BDCB7",
      "severity": "CRITICAL",
      "risk_score": 100,
      "suppressed": false,
      "principal": "canary-prod-db-backup",
      "chain": ["Discovery", "Credential Access", "Privilege Escalation"]
    }
  ]
}
```

It also writes one structured log line per incident,
`{"canary_incident": {...}}`, so the full analysis is queryable in CloudWatch
Logs Insights without an extra data store.

## 7. Joint validation test

Once both halves are deployed:

```bash
# Person A (red team) - use the planted key
aws s3 ls --profile canary
aws sts get-caller-identity --profile canary
aws iam create-access-key --user-name canary-prod-db-backup --profile canary

# Person B (blue team) - confirm the alert
aws logs tail /aws/lambda/canary-identity-detector --follow
```

Expected: a Slack alert within 1-2 minutes, severity `CRITICAL`, risk >= 75, and
a chain reading `Discovery -> Persistence`.
