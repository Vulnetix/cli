resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "mysql"
  publicly_accessible = var.db_public
}
