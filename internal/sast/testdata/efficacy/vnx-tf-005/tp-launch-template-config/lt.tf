resource "aws_launch_template" "nodes" {
  name_prefix   = "nodes-"
  image_id      = var.ami
  instance_type = "m6i.large"

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 50
      volume_type = "gp3"
~>      encrypted   = "false"
    }
  }
}
