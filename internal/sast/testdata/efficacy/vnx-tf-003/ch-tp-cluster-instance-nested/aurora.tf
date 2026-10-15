resource "aws_rds_cluster_instance" "reader" {
  count              = 2
  identifier         = "reader-${count.index}"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.r6g.large"
  engine             = aws_rds_cluster.main.engine

  timeouts {
    create = "60m"
  }

~>  publicly_accessible = true

  tags = {
    Name = "reader"
  }
}
