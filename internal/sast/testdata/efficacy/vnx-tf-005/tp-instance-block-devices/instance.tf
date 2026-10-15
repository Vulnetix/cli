resource "aws_instance" "app" {
  ami           = var.ami
  instance_type = "t3.large"

  root_block_device {
    volume_size = 30
~>    encrypted   = false
  }

  ebs_block_device {
    device_name = "/dev/sdf"
    volume_size = 200
~>    encrypted   = false
  }
}

resource "aws_launch_configuration" "workers" {
  image_id      = var.ami
  instance_type = "m5.large"

  root_block_device {
~>    encrypted = false
  }
}
