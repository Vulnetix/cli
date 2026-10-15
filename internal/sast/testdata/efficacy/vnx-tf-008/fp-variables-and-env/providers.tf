provider "aws" {
  region     = var.region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

provider "aws" {
  alias                    = "shared"
  region                   = "us-east-1"
  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "deploy"
}

provider "aws" {
  alias      = "vault"
  access_key = data.vault_aws_access_credentials.creds.access_key
  secret_key = "${data.vault_aws_access_credentials.creds.secret_key}"
}

output "secret" {
  value     = aws_iam_access_key.ci.secret
  sensitive = true
}
