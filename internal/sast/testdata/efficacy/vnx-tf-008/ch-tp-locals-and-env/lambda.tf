locals {
~>  aws_access_key_id     = "@@sample:AKIA[A-Z2-7]{16}@@"
~>  aws_secret_access_key = "@@sample:[A-Za-z0-9/+]{40}@@"
}

resource "aws_lambda_function" "sync" {
  function_name = "sync"
  role          = aws_iam_role.sync.arn
  handler       = "main.handler"
  runtime       = "python3.12"

  environment {
    variables = {
~>      AWS_SECRET_ACCESS_KEY = "@@sample:[A-Za-z0-9/+]{40}@@"
      REGION                = "us-east-1"
    }
  }
}
