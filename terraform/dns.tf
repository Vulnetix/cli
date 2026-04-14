# Proxied record for cli.vulnetix.com (no origin server — Cloudflare handles all requests via redirect rules)
resource "cloudflare_dns_record" "cli_root" {
  zone_id = var.cloudflare_zone_id
  name    = "cli"
  type    = "A"
  content = "192.0.2.1"
  proxied = true
  ttl     = 1
}

# CLI docs CNAME pointing to GitHub Pages (imported from Cloudflare dashboard)
resource "cloudflare_dns_record" "cli_docs" {
  zone_id = var.cloudflare_zone_id
  name    = "docs.cli"
  type    = "CNAME"
  content = "vulnetix.github.io"
  proxied = false
  ttl     = 300
}
