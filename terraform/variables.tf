variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for deployment"
}

variable "canary_username" {
  type        = string
  default     = "canary-prod-db-backup"
  description = "Name of the decoy IAM user"
}

variable "slack_webhook_url" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Optional Slack/Discord Webhook URL for alerts"
}