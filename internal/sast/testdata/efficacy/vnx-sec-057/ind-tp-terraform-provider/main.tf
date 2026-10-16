terraform {
  required_providers {
    grafana = { source = "grafana/grafana" }
  }
}

provider "grafana" {
  url  = "https://grafana.acme.internal"
~>  auth = "glsa_@@sample:[A-Za-z0-9]{32}@@_@@sample:[a-f0-9]{8}@@"
}
