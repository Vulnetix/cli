resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
~>  publicly_accessible = true
  skip_final_snapshot = true
}
