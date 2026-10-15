module "orders_db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "6.5.0"

  identifier          = "orders"
  engine              = "postgres"
~>  publicly_accessible = true
}
