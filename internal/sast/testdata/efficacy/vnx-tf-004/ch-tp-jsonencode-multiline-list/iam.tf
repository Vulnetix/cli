resource "aws_iam_policy" "ops" {
  name = "ops"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadLogs"
        Effect = "Allow"
        Action = ["logs:GetLogEvents"]
        Resource = "*"
      },
      {
        Sid = "Everything"
~>        Action = [
          "*",
        ]
        Resource = "*"
      },
    ]
  })
}
