variable "publicly_accessible" {
  type    = bool
  default = true
}

resource "aws_db_instance" "main" {
  identifier          = "app-db"
  instance_class      = "db.t3.micro"
  publicly_accessible = var.publicly_accessible
}

module "db" {
  source              = "terraform-aws-modules/rds/aws"
  publicly_accessible = false
}
