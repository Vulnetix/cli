# Proxied record for cli.vulnetix.com (no origin server — Cloudflare handles all requests via redirect rules)
resource "cloudflare_dns_record" "cli_root" {
  zone_id = var.cloudflare_zone_id
  name    = "cli"
  type    = "A"
  content = "192.0.2.1"
  proxied = true
  ttl     = 1
}
