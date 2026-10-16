resource "aws_cognito_user_pool" "staff" {
  name              = "staff"
  mfa_configuration = "ON"

  software_token_mfa_configuration {
    enabled = true
  }
}
