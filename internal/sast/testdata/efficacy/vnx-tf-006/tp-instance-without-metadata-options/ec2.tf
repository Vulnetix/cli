~>resource "aws_instance" "web_host" {
  ami           = var.ami
  instance_type = "t2.nano"

  vpc_security_group_ids = [aws_security_group.web.id]
  subnet_id              = aws_subnet.web.id
  user_data              = file("${path.module}/init.sh")

  tags = {
    Name = "web-host"
  }
}

resource "aws_ebs_volume" "web" {
  availability_zone = "eu-west-1a"
  size              = 1
}

~>resource "aws_launch_template" "batch" {
  name_prefix   = "batch-"
  image_id      = var.ami
  instance_type = "c6i.large"
}

resource "aws_instance" "imdsv2" {
  ami           = var.ami
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}
