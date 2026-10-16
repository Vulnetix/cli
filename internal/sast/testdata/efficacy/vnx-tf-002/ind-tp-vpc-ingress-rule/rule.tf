resource "aws_vpc_security_group_ingress_rule" "all_mysql" {
  security_group_id = aws_security_group.db.id
  ip_protocol       = "tcp"
  from_port         = 3306
  to_port           = 3306
~>  cidr_ipv4         = "0.0.0.0/0"
}
