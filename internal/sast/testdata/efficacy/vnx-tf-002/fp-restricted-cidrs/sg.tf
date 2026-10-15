resource "aws_security_group" "internal" {
  name   = "internal"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "192.168.10.0/24"]
  }

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
}

resource "aws_vpc_security_group_ingress_rule" "office" {
  security_group_id = aws_security_group.internal.id
  cidr_ipv4         = "203.0.113.0/24"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
