resource "aws_instance" "web" {
  ami           = "ami-0abcdef"
  instance_type = "t3.micro"
  # publicly_accessible = true
}

resource "aws_lb" "front" {
  name     = "front"
  internal = false
}
