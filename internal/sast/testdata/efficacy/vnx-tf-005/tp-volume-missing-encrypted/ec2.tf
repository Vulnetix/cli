resource "aws_instance" "web" {
  ami           = var.ami
  instance_type = "t3.micro"
}

~>resource "aws_ebs_volume" "web_storage" {
  availability_zone = aws_instance.web.availability_zone
  # unencrypted volume
  #encrypted         = false
  size = 1
  tags = {
    Name = "web-storage"
  }
}

resource "aws_volume_attachment" "web" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.web_storage.id
  instance_id = aws_instance.web.id
}

~>resource "aws_ebs_volume" "scratch" {
  availability_zone = "eu-west-1b"
  size              = 50
  type              = "gp3"
}
