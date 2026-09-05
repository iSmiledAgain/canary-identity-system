resource "aws_cloudwatch_event_rule" "canary_rule" {
  name        = "canary-identity-trigger"
  description = "Fires whenever API requests are made using Canary Credentials"

  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"],
    "detail" = {
      "userIdentity" = {
        "userName" = [aws_iam_user.canary_user.name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "send_to_lambda" {
  rule      = aws_cloudwatch_event_rule.canary_rule.name
  target_id = "CanaryLambdaTarget"
  arn       = aws_lambda_function.canary_detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.canary_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.canary_rule.arn
}