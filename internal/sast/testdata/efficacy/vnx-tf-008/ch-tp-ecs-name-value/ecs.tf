resource "aws_ecs_task_definition" "worker" {
  family = "worker"
  container_definitions = jsonencode([
    {
      name  = "worker"
      image = "acme/worker:1.4.2"
      environment = [
~>        { name = "AWS_ACCESS_KEY_ID", value = "@@sample:AKIA[A-Z2-7]{16}@@" },
        {
          name  = "AWS_SECRET_ACCESS_KEY"
~>          value = "@@sample:[A-Za-z0-9/+]{40}@@"
        },
        { name = "LOG_LEVEL", value = "info" },
      ]
    }
  ])
}
