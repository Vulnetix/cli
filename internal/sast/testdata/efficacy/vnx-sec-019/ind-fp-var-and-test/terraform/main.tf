resource "kubernetes_secret" "sa" {
  data = {
    type        = "service_account"
    private_key = "${var.gcp_private_key}"
  }
}
