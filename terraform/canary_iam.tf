# Decoy IAM User
resource "aws_iam_user" "canary_user" {
  name = var.canary_username
  tags = {
    Type        = "CanaryIdentity"
    Environment = "Deception"
  }
}

# Access Key Pair (This will be planted on target systems)
resource "aws_iam_access_key" "canary_key" {
  user = aws_iam_user.canary_user.name
}

# Safety Policy: Explicit Deny All to prevent real unauthorized access
resource "aws_iam_user_policy" "canary_deny_all" {
  name = "CanaryExplicitDenyAll"
  user = aws_iam_user.canary_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}