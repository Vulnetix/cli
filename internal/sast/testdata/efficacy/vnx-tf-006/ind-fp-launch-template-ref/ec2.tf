resource "aws_instance" "fleet" {
  instance_type = "t3.micro"

  launch_template {
    id      = aws_launch_template.hardened.id
    version = "$Latest"
  }
}
