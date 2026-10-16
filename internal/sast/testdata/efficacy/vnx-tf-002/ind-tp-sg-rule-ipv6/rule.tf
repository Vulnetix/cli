resource "aws_security_group_rule" "db" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
~>  ipv6_cidr_blocks = ["::/0"]
  security_group_id = aws_security_group.db.id
}
