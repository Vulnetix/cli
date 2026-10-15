resource "aws_cognito_user_pool" "users" {
  name = "customers"

~>  mfa_configuration = "OFF"

  password_policy {
    minimum_length = 12
  }
}
