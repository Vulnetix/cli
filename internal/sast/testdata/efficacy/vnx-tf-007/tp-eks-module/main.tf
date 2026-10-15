module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "platform"
  cluster_version = "1.30"

~>  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
}

module "eks_v21" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name = "edge"
~>  endpoint_public_access = true
}
