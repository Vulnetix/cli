terraform {
  backend "azurerm" {
    storage_account_name = "acmetfstate"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
~>    access_key           = "@@sample:[A-Za-z0-9+/]{86}@@=="
  }
}
