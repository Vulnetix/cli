resource "aws_ebs_volume" "cache" {
  availability_zone = "eu-west-1b"
  size              = 20
}
