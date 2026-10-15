resource "aws_cognito_user_pool" "users" {
  name              = "customers"
  mfa_configuration = "ON"

  software_token_mfa_configuration {
    enabled = true
  }
}
