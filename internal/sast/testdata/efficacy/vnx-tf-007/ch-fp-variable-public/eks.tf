resource "aws_eks_cluster" "cfg" {
  name     = "cfg"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids             = var.subnets
    endpoint_public_access = var.public_endpoint
    public_access_cidrs    = var.admin_cidrs
  }
}

resource "aws_opensearch_domain" "logs" {
  domain_name = "logs"
  endpoint_public_access = true
}
