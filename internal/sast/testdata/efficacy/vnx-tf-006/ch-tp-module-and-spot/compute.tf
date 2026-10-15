module "builder" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 5.6"

  name          = "builder"
  instance_type = "c6i.large"

  metadata_options = {
    http_endpoint               = "enabled"
~>    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}

resource "aws_spot_instance_request" "batch" {
  ami           = var.ami
  spot_price    = "0.05"
  instance_type = "c6i.large"

  metadata_options {
~>    http_tokens = "optional"
  }
}
