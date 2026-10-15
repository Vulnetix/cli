resource "aws_iam_account_password_policy" "org" {
  minimum_password_length = 14
~>  max_password_age        = 365
}
