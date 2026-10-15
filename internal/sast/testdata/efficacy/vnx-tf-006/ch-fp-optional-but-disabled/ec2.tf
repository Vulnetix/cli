resource "aws_instance" "airgapped" {
  ami           = var.ami
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "disabled"
    http_tokens   = "optional"
  }
}

module "lambda_like" {
  source = "./modules/worker"

  settings = {
    http_tokens = "optional"
  }
}
