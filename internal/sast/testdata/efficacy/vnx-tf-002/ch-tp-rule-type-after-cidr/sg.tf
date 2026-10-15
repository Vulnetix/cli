resource "aws_security_group_rule" "rdp" {
  security_group_id = aws_security_group.win.id
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
~>  cidr_blocks       = ["0.0.0.0/0"]
  type              = "ingress"
}
