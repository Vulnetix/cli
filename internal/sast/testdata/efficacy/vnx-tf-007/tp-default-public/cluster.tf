~>resource "aws_eks_cluster" "dev" {
  name     = "dev"
  role_arn = aws_iam_role.cluster.arn
  version  = "1.30"

  vpc_config {
    subnet_ids = aws_subnet.private[*].id
  }

  depends_on = [aws_iam_role_policy_attachment.cluster]
}

resource "aws_eks_node_group" "dev" {
  cluster_name  = aws_eks_cluster.dev.name
  node_role_arn = aws_iam_role.node.arn
  subnet_ids    = aws_subnet.private[*].id
}
