resource "aws_mq_broker" "events" {
  broker_name         = "events"
  engine_type         = "ActiveMQ"
  publicly_accessible = true
}

resource "aws_neptune_cluster_instance" "graph" {
  cluster_identifier  = aws_neptune_cluster.g.id
  publicly_accessible = true
}
