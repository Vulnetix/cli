data "aws_iam_policy_document" "read" {
  statement {
    actions   = ["s3:*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_policy" "logs" {
  name = "logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "lambda" {
  name = "lambda"
  assume_role_policy = <<JSON
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" }
    }
  ]
}
JSON
}
