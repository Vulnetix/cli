resource "aws_eks_cluster" "prod" {
  name     = "prod"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = var.subnets
~>    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}
