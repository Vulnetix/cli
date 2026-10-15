resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = var.private_subnets
    endpoint_private_access = true
~>    endpoint_public_access  = true
  }
}

resource "aws_eks_cluster" "staging" {
  name     = "staging"
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids             = var.private_subnets
~>    endpoint_public_access = true
    public_access_cidrs    = ["0.0.0.0/0"]
  }
}
