module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name                         = "prod"
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = ["198.51.100.0/24"]
}
