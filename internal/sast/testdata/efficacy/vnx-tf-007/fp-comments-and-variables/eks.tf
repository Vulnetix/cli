# endpoint_public_access = true exposes the API server.
resource "aws_eks_cluster" "app" {
  name     = "app"
  role_arn = aws_iam_role.cluster.arn
  vpc_config {
    subnet_ids             = var.private_subnets
    # endpoint_public_access = true
    endpoint_public_access = var.public_endpoint
  }
}

resource "aws_opensearch_domain" "search" {
  domain_name = "search"
  endpoint_public_access = true
}
