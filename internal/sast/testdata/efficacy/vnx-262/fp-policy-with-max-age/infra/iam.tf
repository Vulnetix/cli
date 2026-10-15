resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

data "aws_iam_account_password_policy" "current" {}
