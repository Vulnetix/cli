terraform {
  required_providers {
    digitalocean = {
      source = "digitalocean/digitalocean"
    }
  }
}

provider "digitalocean" {
~>  token = "dop_v1_@@sample:[a-f0-9]{64}@@"
}
