resource "aws_ebs_volume" "logs" {
  availability_zone = "eu-west-1a"
  size              = 20
}
