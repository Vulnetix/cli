resource "azuread_user" "svc" {
  user_principal_name         = "svc@example.com"
  display_name                = "Service"
~>  disable_password_expiration = true
}
