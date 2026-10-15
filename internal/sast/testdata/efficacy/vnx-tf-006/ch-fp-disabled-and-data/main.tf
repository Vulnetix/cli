resource "aws_instance" "isolated" {
  ami           = var.ami
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "disabled"
  }
}

data "aws_instance" "existing" {
  instance_id = "i-0123456789abcdef0"
}

resource "aws_instance" "tokens" {
  ami           = var.ami
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = var.http_tokens
  }
}
