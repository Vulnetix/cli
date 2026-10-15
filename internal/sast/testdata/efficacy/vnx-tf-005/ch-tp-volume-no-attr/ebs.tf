~>resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"

  tags = {
    Name      = "scratch"
    encrypted = "yes"
  }
}

resource "aws_volume_attachment" "scratch" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.scratch.id
  instance_id = aws_instance.app.id
}
