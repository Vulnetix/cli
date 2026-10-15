module "web_sg" {
  source = "terraform-aws-modules/security-group/aws"

  name                = "web"
  vpc_id              = var.vpc_id
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "https-443-tcp"]
  egress_cidr_blocks  = ["0.0.0.0/0"]
  egress_rules        = ["all-all"]
}

module "internal_sg" {
  source = "terraform-aws-modules/security-group/aws"

  name                = "internal"
  ingress_cidr_blocks = ["10.0.0.0/16"]
  ingress_rules       = ["ssh-tcp"]
}

module "vpc" {
  source               = "terraform-aws-modules/vpc/aws"
  public_subnets       = ["10.0.1.0/24"]
  ingress_cidr_blocks  = ["0.0.0.0/0"]
}
