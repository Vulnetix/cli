provider "aws" {
  region     = "us-east-1"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

provider "aws" {
  alias      = "dr"
  region     = "us-west-2"
  access_key = data.aws_ssm_parameter.ak.value
  secret_key = "${data.aws_ssm_parameter.sk.value}"
}
