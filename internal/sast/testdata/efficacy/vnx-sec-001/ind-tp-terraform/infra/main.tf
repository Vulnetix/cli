provider "aws" {
  region     = "us-east-1"
~>  access_key = "@@sample:ASIA[A-Z2-7]{16}@@"
  secret_key = var.aws_secret
}
