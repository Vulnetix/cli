resource "aws_instance" "web" {
  ami           = "ami-0abc"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "enabled"
~>    http_tokens   = "optional"
  }
}
