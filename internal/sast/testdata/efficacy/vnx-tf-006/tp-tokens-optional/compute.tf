resource "aws_instance" "api" {
  ami           = var.ami
  instance_type = "t3.small"

  metadata_options {
    http_endpoint = "enabled"
~>    http_tokens   = "optional"
  }
}

resource "aws_launch_template" "workers" {
  name_prefix = "workers-"
  image_id    = var.ami

  metadata_options {
~>    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}

resource "aws_launch_configuration" "legacy" {
  image_id      = var.ami
  instance_type = "t3.micro"
  metadata_options {
~>    http_tokens = "optional"
  }
}
