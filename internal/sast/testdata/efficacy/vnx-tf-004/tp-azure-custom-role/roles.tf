resource "azurerm_role_definition" "ops" {
  name        = "ops-everything"
  scope       = data.azurerm_subscription.primary.id
  description = "Ops custom role"

  permissions {
~>    actions     = ["*"]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.primary.id]
}
