resource "azuread_user" "backup_svc" {
  user_principal_name         = "svc-backup@corp.example.com"
  display_name                = "Backup service"
  password                    = random_password.backup.result
~>  disable_password_expiration = true
}
