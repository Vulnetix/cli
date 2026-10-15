resource "aws_eks_cluster" "prod" {
  name     = "prod"
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = var.private_subnets
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}

module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "internal"
  cluster_version = "1.30"
}
