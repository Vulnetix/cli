resource "aws_instance" "runner" {
  ami           = var.ami
  instance_type = "t3.medium"

~>  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }
}
