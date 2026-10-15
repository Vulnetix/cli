resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = var.vpc_id

  ingress {
    description = "http to https"
    from_port   = 80
    to_port     = 443
    protocol    = "tcp"
~>    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = -1
    self        = false
    from_port   = 0
    to_port     = 0
~>    cidr_blocks = ["0.0.0.0/0"]
  }
}
