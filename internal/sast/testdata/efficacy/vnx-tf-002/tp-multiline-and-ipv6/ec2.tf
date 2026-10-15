resource "aws_security_group" "web_node" {
  name   = "web-node"
  vpc_id = aws_vpc.web.id

  ingress {
    from_port = 8080
    to_port   = 8080
    protocol  = "tcp"
~>    cidr_blocks = [
    "0.0.0.0/0"]
  }
  ingress {
    from_port        = 6379
    to_port          = 6379
    protocol         = "tcp"
~>    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    from_port = 9200
    to_port   = 9300
    protocol  = "tcp"
~>    cidr_blocks = [
      "10.1.0.0/16",
      "0.0.0.0/0",
    ]
  }
}
