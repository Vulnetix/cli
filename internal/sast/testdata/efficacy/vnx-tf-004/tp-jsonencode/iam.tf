resource "aws_iam_policy" "admin" {
  name = "ci-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
~>        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_user_policy" "ops" {
  name = "ops"
  user = aws_iam_user.ops.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
~>      Action   = ["*"]
      Effect   = "Allow"
      Resource = "arn:aws:s3:::ops-*"
    }]
  })
}
