resource "aws_redshift_cluster" "analytics" {
  cluster_identifier = "analytics"
  node_type          = "ra3.xlplus"
~>  publicly_accessible = true
}

resource "aws_dms_replication_instance" "migrate" {
  replication_instance_id    = "migrate"
  replication_instance_class = "dms.t3.medium"
~>  publicly_accessible        = true
}
