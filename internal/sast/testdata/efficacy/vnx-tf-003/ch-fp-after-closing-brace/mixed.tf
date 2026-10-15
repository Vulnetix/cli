resource "aws_db_instance" "main" {
  identifier          = "main"
  publicly_accessible = false
}

resource "aws_dms_endpoint" "src" {
  endpoint_id   = "src"
  endpoint_type = "source"
}

resource "aws_mq_broker" "b" {
  broker_name         = "b"
  publicly_accessible = true
}
