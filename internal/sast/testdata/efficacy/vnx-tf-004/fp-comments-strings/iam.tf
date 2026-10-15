# Never write Action = "*" in a policy.
resource "aws_iam_policy" "readonly" {
  name        = "readonly"
  description = "replaces the old Action = \"*\" policy"
  policy = jsonencode({
    Statement = [
      {
        Effect = "Allow"
        # Action = "*"
        // actions = ["*"]
        Action   = "ec2:Describe*"
        Resource = "*"
      },
    ]
  })
}
