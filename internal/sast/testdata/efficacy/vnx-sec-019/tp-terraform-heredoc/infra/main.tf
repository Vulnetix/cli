resource "kubernetes_secret" "gcp" {
  metadata { name = "gcp-sa" }
  data = {
~>    "key.json" = "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQ@@sample:[A-Za-z0-9+/]{64}@@\\n@@sample:[A-Za-z0-9+/]{64}@@\\n-----END PRIVATE KEY-----\\n\"}"
  }
}
