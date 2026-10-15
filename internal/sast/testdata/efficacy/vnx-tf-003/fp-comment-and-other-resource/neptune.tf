resource "aws_neptune_cluster_instance" "default" {
  cluster_identifier = aws_neptune_cluster.default.id
  instance_class     = "db.t3.medium"
  #publicly_accessible = true # no longer supported
}

# publicly_accessible = true would expose the database.
resource "aws_mq_broker" "events" {
  broker_name         = "events"
  engine_type         = "RabbitMQ"
  publicly_accessible = true
}

resource "aws_db_instance" "notes" {
  identifier = "notes"
  // publicly_accessible = true
}
