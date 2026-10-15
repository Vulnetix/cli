resource "aws_instance" "api" {
  ami           = var.ami
  instance_type = "t3.small"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

resource "aws_instance" "offline" {
  ami = var.ami
  metadata_options {
    http_endpoint = "disabled"
  }
}

resource "aws_launch_template" "nodes" {
  image_id = var.ami
  metadata_options {
    http_tokens = var.http_tokens
  }
}

resource "aws_instance" "from_template" {
  launch_template {
    id      = aws_launch_template.nodes.id
    version = "$Latest"
  }
}
