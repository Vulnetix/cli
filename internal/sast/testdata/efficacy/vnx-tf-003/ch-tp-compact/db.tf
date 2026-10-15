resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
~>  publicly_accessible=true
  skip_final_snapshot = true
}
