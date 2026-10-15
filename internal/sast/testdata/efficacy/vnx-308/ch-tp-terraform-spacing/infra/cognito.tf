resource "aws_cognito_user_pool" "customers" {
  name                     = "customers"
~>  mfa_configuration        = "OFF"
  auto_verified_attributes = ["email"]
}
