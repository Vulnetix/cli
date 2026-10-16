resource "aws_launch_template" "asg" {
  name_prefix   = "asg-"
  image_id      = "ami-0abc"
  instance_type = "m5.large"

  metadata_options {
    http_put_response_hop_limit = 2
~>    http_tokens                 = "optional"
  }
}
