resource "aws_instance" "app" {
  ami           = var.ami
  instance_type = "t3.micro"
}
