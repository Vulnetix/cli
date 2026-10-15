# Do not use cidr_blocks = ["0.0.0.0/0"] on ingress.
resource "aws_security_group" "locked" {
  name = "locked"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    # cidr_blocks = ["0.0.0.0/0"]
    // ipv6_cidr_blocks = ["::/0"]
    cidr_blocks = [var.vpn_cidr]
    description = "was cidr_blocks = [\"0.0.0.0/0\"]"
  }
}
