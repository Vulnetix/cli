resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = var.subnet_ids
~>    endpoint_public_access  = true
    endpoint_private_access = true
  }
}
