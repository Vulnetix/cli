resource "azurerm_storage_account" "data" {
  name = "contosodata"
}

locals {
~>  storage_account_access_key = "@@sample:[A-Za-z0-9+/]{86}==@@"
}
