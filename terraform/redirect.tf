# The zone's dynamic redirect ruleset (one per phase per zone) is owned by
# vdb-site/terraform/dns.tf, cloudflare_ruleset.dynamic_redirects. Two copies
# overwrote each other on every apply, so this one is released without
# destroying the live ruleset. Add cli.vulnetix.com redirects there.
removed {
  from = cloudflare_ruleset.redirects

  lifecycle {
    destroy = false
  }
}
