resource "aws_vpc_security_group_ingress_rule" "any" {
  security_group_id = aws_security_group.app.id
  ip_protocol       = "-1"
~>  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "any_v6" {
  security_group_id = aws_security_group.app.id
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
~>  cidr_ipv6         = "::/0"
}
