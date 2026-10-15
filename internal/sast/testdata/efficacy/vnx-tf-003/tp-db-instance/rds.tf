resource "aws_db_instance" "main" {
  identifier           = "app-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "app"
  manage_master_user_password = true
~>  publicly_accessible  = true
  skip_final_snapshot  = true
}

resource "aws_db_instance" "replica" {
  replicate_source_db = aws_db_instance.main.identifier
  instance_class      = "db.t3.micro"
~>  publicly_accessible="true"
}
