variable "do_token" {
  type      = string
  sensitive = true
}
provider "digitalocean" {
  token = var.do_token
}
