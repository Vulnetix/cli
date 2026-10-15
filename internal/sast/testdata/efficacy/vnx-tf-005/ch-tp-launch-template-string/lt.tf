resource "aws_launch_template" "api" {
  name_prefix = "api-"
  image_id    = var.ami

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 30
      delete_on_termination = true
~>      encrypted             = "false"
    }
  }
}
