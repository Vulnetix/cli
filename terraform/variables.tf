variable "cloudflare_api_token" {
  description = "Cloudflare API token for DNS management"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for vulnetix.com"
  type        = string
  default     = "d3aeda6727dbbae840f5abb1aab1444d"
}
