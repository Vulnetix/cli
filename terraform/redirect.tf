# Zone-level dynamic redirect rules (one ruleset per phase per zone)
# Reconciled against live Cloudflare config on 2026-04-17.
resource "cloudflare_ruleset" "redirects" {
  zone_id     = var.cloudflare_zone_id
  name        = "default"
  description = ""
  kind        = "zone"
  phase       = "http_request_dynamic_redirect"

  rules = [
    # --- Apex vulnetix.com root → www (exact-match, 308) ---
    {
      ref         = "583a4505883743a39d0079b42e279da4"
      description = "redirect vulnetix.com to www"
      expression  = "(http.request.full_uri wildcard r\"https://vulnetix.com/\")"
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 308
          preserve_query_string = true
          target_url = {
            expression = "wildcard_replace(http.request.full_uri, r\"https://vulnetix.com/\", r\"https://www.vulnetix.com/\")"
          }
        }
      }
    },

    # --- Apex vulnetix.com SSR pages → www (so bots / AI agents get SSR HTML on apex) ---
    {
      ref         = "apex_ssr_pages_redirect"
      description = "Redirect vulnetix.com SSR pages to www"
      expression  = "(http.host eq \"vulnetix.com\" and http.request.uri.path in {\"/features/ai-features\" \"/features/code-scanner\" \"/features/pipeline-integrations\" \"/vdb\" \"/vdb-console\" \"/security\"})"
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 301
          preserve_query_string = true
          target_url = {
            expression = "concat(\"https://www.vulnetix.com\", http.request.uri.path)"
          }
        }
      }
    },

    # --- vulnetix.app → www.vulnetix.com ---
    {
      ref         = "1931e4b8ebd1406fa8194b8fa29cc712"
      description = "Redirect to a different domain [Template]"
      expression  = "(http.host eq \"vulnetix.app\")"
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 301
          preserve_query_string = true
          target_url = {
            expression = "concat(\"https://www.vulnetix.com\", http.request.uri.path)"
          }
        }
      }
    },

    # --- Any HTTP → HTTPS ---
    {
      ref         = "006b9f8ee8244698b4a174daafe80cf3"
      description = "Redirect from HTTP to HTTPS [Template]"
      expression  = "(http.request.full_uri wildcard r\"http://*\")"
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 301
          preserve_query_string = true
          target_url = {
            expression = "wildcard_replace(http.request.full_uri, r\"http://*\", r\"https://$${1}\")"
          }
        }
      }
    },

    # --- claude-docs.vdb.vulnetix.com → ai-docs.vulnetix.com ---
    {
      ref         = "d1262fcf48754932984c020c1ade8b70"
      description = "301 redirect old docs domain to ai-docs.vulnetix.com"
      expression  = "(http.host eq \"claude-docs.vdb.vulnetix.com\")"
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 301
          preserve_query_string = true
          target_url = {
            expression = "concat(\"https://ai-docs.vulnetix.com\", http.request.uri.path)"
          }
        }
      }
    },

    # --- cli.vulnetix.com rules ---
    {
      ref         = "install_script_redirect"
      description = "Redirect /install.sh to raw GitHub content"
      expression  = "(http.host eq \"cli.vulnetix.com\" and http.request.uri.path eq \"/install.sh\")"
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 302
          preserve_query_string = false
          target_url = {
            value = "https://github.com/Vulnetix/cli/releases/latest/download/install.sh"
          }
        }
      }
    },
    {
      ref         = "cli_root_redirect"
      description = "Redirect root to GitHub repo"
      expression  = "(http.host eq \"cli.vulnetix.com\" and http.request.uri.path eq \"/\")"
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 302
          preserve_query_string = false
          target_url = {
            value = "https://github.com/Vulnetix/cli"
          }
        }
      }
    }
  ]
}
