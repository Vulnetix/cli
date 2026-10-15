resource "azuread_user" "alice" {
  user_principal_name         = "alice@example.com"
  disable_password_expiration = false
}
