provider "aws" {
  region     = "us-west-2"
~>  secret_key = "@@sample:[A-Za-z0-9/+]{40}@@"
}
