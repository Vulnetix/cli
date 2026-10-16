resource "aws_cognito_user_pool" "customers" {
  name = "customers-prod"

  password_policy {
    minimum_length = 12
  }

~>  mfa_configuration = "OFF"
}
