output "canary_access_key_id" {
  value       = aws_iam_access_key.canary_key.id
  description = "The Access Key ID for planting"
}

output "canary_secret_access_key" {
  value       = aws_iam_access_key.canary_key.secret
  sensitive   = true
  description = "The Secret Access Key for planting"
}

output "canary_user_arn" {
  value       = aws_iam_user.canary_user.arn
  description = "The ARN of the decoy IAM user"
}