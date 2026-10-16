resource "aws_security_group" "app" {
  name = "app"

  ingress {
    from_port = 8080
    to_port   = 8080
    protocol  = "tcp"
~>    cidr_blocks = [
      "10.0.0.0/8",
      "0.0.0.0/0",
    ]
  }
}
