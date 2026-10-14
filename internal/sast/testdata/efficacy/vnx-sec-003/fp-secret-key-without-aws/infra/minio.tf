provider "minio" {
  minio_server = "minio.internal:9000"
  secret_key   = "@@sample:[A-Za-z0-9/+]{40}@@"
}
