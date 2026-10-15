resource "aws_db_instance" "main" {
  identifier          = "app-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = false
}

resource "aws_rds_cluster_instance" "reader" {
  cluster_identifier  = aws_rds_cluster.main.id
  instance_class      = "db.r6g.large"
  publicly_accessible = false
}
