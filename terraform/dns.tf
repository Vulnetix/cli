# CLI docs CNAME pointing to GitHub Pages (imported from Cloudflare dashboard)
resource "cloudflare_dns_record" "cli_docs" {
  zone_id = var.cloudflare_zone_id
  name    = "docs.cli"
  type    = "CNAME"
  content = "vulnetix.github.io"
  proxied = false
  ttl     = 300
}
