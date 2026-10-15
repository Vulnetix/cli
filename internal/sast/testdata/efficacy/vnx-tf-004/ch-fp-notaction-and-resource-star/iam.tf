resource "aws_iam_policy" "boundary" {
  name = "boundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        NotAction = "*"
        Resource  = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = "*"
        Principal = { AWS = "*" }
      }
    ]
  })
}
