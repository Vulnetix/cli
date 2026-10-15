resource "azurerm_role_definition" "reader" {
  name  = "vm-reader"
  scope = data.azurerm_subscription.primary.id

  permissions {
    actions     = ["Microsoft.Compute/virtualMachines/read"]
    not_actions = ["*"]
    data_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.primary.id]
}
