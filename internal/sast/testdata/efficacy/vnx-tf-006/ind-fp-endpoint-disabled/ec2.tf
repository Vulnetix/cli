resource "aws_instance" "isolated" {
  ami           = "ami-0abc"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "disabled"
  }
}
