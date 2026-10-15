module "analytics_db" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 9.0"

  name           = "analytics"
  engine         = "aurora-postgresql"
~>  publicly_accessible = true
}

resource "aws_redshift_cluster" "dw" {
  cluster_identifier = "dw"
  node_type          = "dc2.large"
~>  publicly_accessible = "true"
}
