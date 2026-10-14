resource "azurerm_storage_share" "media" {
  name                 = "media"
  storage_account_name = "contosodata"
  quota                = 50
}

locals {
~>  storage_account_access_key = "@@sample:[A-Za-z0-9+/]{86}@@=="
}
