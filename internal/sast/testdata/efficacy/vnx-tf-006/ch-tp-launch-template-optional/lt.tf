resource "aws_launch_template" "web" {
  name_prefix   = "web-"
  image_id      = var.ami
  instance_type = "t3.small"

  metadata_options {
    http_endpoint               = "enabled"
~>    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}
