module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name                         = "ops"
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = ["203.0.113.0/24"]
}

resource "aws_eks_node_group" "ng" {
  cluster_name    = module.eks.cluster_name
  node_group_name = "ng"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnets
  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
}
