resource "aws_launch_configuration" "workers" {
  name_prefix   = "workers-"
  image_id      = data.aws_ami.al2.id
  instance_type = "m5.large"

  root_block_device {
    volume_size = 50
~>    encrypted   = false
  }
}
