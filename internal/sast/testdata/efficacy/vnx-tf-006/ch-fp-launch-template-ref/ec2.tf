resource "aws_instance" "worker" {
  count = 3

  launch_template {
    id      = aws_launch_template.worker.id
    version = "$Latest"
  }
}

resource "aws_launch_template" "worker" {
  image_id = var.ami
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}
