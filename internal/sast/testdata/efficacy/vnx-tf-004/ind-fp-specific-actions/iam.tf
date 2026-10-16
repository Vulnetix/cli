resource "aws_iam_policy" "ro" {
  name = "ro"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::acme", "arn:aws:s3:::acme/*"]
    }]
  })
}
# Action = "*" would be far too broad
