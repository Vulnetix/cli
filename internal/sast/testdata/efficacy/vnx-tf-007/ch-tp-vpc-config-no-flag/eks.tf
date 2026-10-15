~>resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = aws_iam_role.eks.arn
  version  = "1.30"

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
  }
}
