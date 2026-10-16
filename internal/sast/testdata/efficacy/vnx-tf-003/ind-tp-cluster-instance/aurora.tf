resource "aws_rds_cluster_instance" "reader" {
  count               = 2
  cluster_identifier  = aws_rds_cluster.main.id
  instance_class      = "db.r6g.large"
  engine              = aws_rds_cluster.main.engine
~>  publicly_accessible = true
}
