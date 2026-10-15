provider "aws" {
  region     = var.region
  access_key = var.aws_access_key
  secret_key = "${var.aws_secret_key}"
}

resource "azurerm_storage_account" "sa" {
  name = "acmestorage"
}

output "storage_access_key" {
  value     = azurerm_storage_account.sa.primary_access_key
  sensitive = true
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}

locals {
  secret_key = aws_iam_access_key.ci.secret
}
