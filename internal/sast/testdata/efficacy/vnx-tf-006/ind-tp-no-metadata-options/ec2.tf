~>resource "aws_instance" "bare" {
  ami           = "ami-0abc"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.a.id
}
