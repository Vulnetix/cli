resource "aws_launch_configuration" "legacy" {
  image_id      = var.ami
  instance_type = "t3.micro"
  metadata_options {
~>    http_tokens = "optional"
  }
}
