resource "aws_eks_cluster" "ops" {
  name     = "ops"
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids             = var.private_subnets
    endpoint_public_access = true
    public_access_cidrs    = ["203.0.113.10/32", "198.51.100.0/24"]
  }
}

resource "aws_eks_cluster" "office" {
  name     = "office"
  role_arn = aws_iam_role.cluster.arn
  vpc_config {
    subnet_ids          = var.private_subnets
    public_access_cidrs = var.office_cidrs
  }
}

module "eks" {
  source                               = "terraform-aws-modules/eks/aws"
  cluster_name                         = "ci"
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = ["192.0.2.0/24"]
}
