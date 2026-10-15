terraform {
  backend "s3" {
    bucket     = "acme-tfstate"
    key        = "prod/terraform.tfstate"
    region     = "eu-west-1"
~>    access_key = "@@sample:AKIA[A-Z0-9]{16}@@"
~>    secret_key="@@sample:[A-Za-z0-9/+]{40}@@"
  }
}

provider "aws" {
  alias      = "dr"
  region     = "eu-central-1"
~>  access_key = "@@sample:ASIA[A-Z0-9]{16}@@"
~>  secret_key = "@@sample:[A-Za-z0-9/+]{40}@@"
  token      = var.session_token
}
