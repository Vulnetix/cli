~>resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1b"
  size              = 50
  type              = "gp3"
}
