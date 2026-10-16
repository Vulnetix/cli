resource "aws_iam_account_password_policy" "baseline" {
  minimum_password_length   = 14
  require_symbols           = true
  max_password_age          = 90
  password_reuse_prevention = 24
}
