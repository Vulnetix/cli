resource "kubernetes_secret" "db" {
  metadata { name = "db" }
  data = {
~>    url = "postgresql://terraform:@@sample:[A-Za-z0-9]{20}@@@pg.prod.acme.internal:5432/app"
  }
}
