resource "aws_eks_cluster" "internal" {
  name     = "internal"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = var.subnets
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}
