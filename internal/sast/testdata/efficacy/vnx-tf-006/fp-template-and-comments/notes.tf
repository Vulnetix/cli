# http_tokens = "optional" enables IMDSv1; never use it.
resource "aws_launch_template" "safe" {
  image_id = var.ami
  metadata_options {
    # http_tokens = "optional"
    http_tokens = "required"
  }
}

data "aws_instance" "existing" {
  instance_id = var.instance_id
}

variable "http_tokens" {
  description = "IMDS token mode; \"optional\" is not allowed"
  default     = "required"
}
