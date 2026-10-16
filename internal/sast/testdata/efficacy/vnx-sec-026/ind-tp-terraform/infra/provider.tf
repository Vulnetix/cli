terraform {
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean" }
  }
}

provider "digitalocean" {
~>  token = "dop_v1_@@sample:[0-9a-f]{64}@@"
}
