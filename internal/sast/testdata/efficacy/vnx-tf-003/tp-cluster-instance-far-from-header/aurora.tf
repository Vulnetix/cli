resource "aws_rds_cluster_instance" "writer" {
  identifier                   = "aurora-writer"
  cluster_identifier           = aws_rds_cluster.main.id
  instance_class               = "db.r6g.large"
  engine                       = aws_rds_cluster.main.engine
  engine_version               = aws_rds_cluster.main.engine_version
  db_subnet_group_name         = aws_db_subnet_group.main.name
  db_parameter_group_name      = aws_db_parameter_group.main.name
  monitoring_interval          = 60
  monitoring_role_arn          = aws_iam_role.monitoring.arn
  performance_insights_enabled = true
  auto_minor_version_upgrade   = true
  apply_immediately            = false
  promotion_tier               = 1
  availability_zone            = "eu-west-1a"
  ca_cert_identifier           = "rds-ca-rsa2048-g1"
  copy_tags_to_snapshot        = true
  preferred_maintenance_window = "sun:03:00-sun:04:00"

  tags = {
    Name = "aurora-writer"
    Team = "data"
  }

~>  publicly_accessible = true
}
