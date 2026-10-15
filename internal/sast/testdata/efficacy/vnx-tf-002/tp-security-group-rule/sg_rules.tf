resource "aws_security_group_rule" "db_in" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
~>  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
}

resource "aws_security_group_rule" "rdp_in" {
  security_group_id = aws_security_group.win.id
~>  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  type              = "ingress"
}

resource "aws_security_group_rule" "all_out" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
}
