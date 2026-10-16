resource "aws_redshift_cluster" "dw" {
  cluster_identifier  = "dw"
  node_type           = "dc2.large"
  master_username     = "admin"
~>  publicly_accessible = true
}
