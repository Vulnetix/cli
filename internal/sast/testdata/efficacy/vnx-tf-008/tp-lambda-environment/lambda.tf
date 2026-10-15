resource "aws_lambda_function" "sync" {
  function_name = "sync"
  role          = aws_iam_role.sync.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"

  environment {
    variables = {
~>      AWS_ACCESS_KEY_ID     = "@@sample:AKIA[A-Z0-9]{16}@@"
~>      AWS_SECRET_ACCESS_KEY = "@@sample:[A-Za-z0-9/+]{40}@@"
      TABLE                 = "sync"
    }
  }
}
