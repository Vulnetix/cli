resource "aws_ecs_task_definition" "api" {
  family = "api"
  container_definitions = jsonencode([
    {
      name  = "api"
      image = "acme/api:2.0.0"
      environment = [
        { name = "AWS_REGION", value = "eu-west-1" },
        { name = "AWS_ACCESS_KEY_ID", value = var.key_id },
      ]
      secrets = [
        {
          name      = "AWS_SECRET_ACCESS_KEY"
          valueFrom = aws_secretsmanager_secret.api.arn
        },
        { name = "CACHE_KEY", value = "@@sample:Z[m]9v[Y]mF[y]Ym[F]6c[X]V4[M]TI[z]ND[U]2N[z]g5[M]GF[i]Y2[R]lZ[m]do@@" },
      ]
    }
  ])
}
