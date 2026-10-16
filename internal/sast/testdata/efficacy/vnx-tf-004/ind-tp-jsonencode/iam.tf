resource "aws_iam_policy" "admin" {
  name = "admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
~>      Action   = "*"
      Resource = "*"
    }]
  })
}
