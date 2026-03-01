# Vulnetix CLI development tasks
# Requires: just (https://github.com/casey/just)

set dotenv-load

# Cloudflare DNS management for docs.cli.vulnetix.com (uses .env)

domain := "docs.cli.vulnetix.com"
target := "vulnetix.github.io"

# Show current DNS records for docs.cli.vulnetix.com
dns-status:
    @echo "Checking DNS records for {{domain}}..."
    @curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?name={{domain}}" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json" | jq '.result[] | {id, type, name, content, proxied, ttl}'

# Create CNAME record pointing to vulnetix.github.io
dns-setup:
    @echo "Creating CNAME record: {{domain}} -> {{target}}"
    @curl -s -X POST \
        "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data '{"type":"CNAME","name":"{{domain}}","content":"{{target}}","ttl":1,"proxied":false}' | jq '{success: .success, id: .result.id, errors: .errors}'

# Remove the CNAME record for docs.cli.vulnetix.com
dns-delete:
    #!/usr/bin/env bash
    set -euo pipefail
    RECORD_ID=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?name={{domain}}&type=CNAME" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json" | jq -r '.result[0].id')
    if [ "$RECORD_ID" = "null" ] || [ -z "$RECORD_ID" ]; then
        echo "No CNAME record found for {{domain}}"
        exit 1
    fi
    echo "Deleting CNAME record $RECORD_ID for {{domain}}..."
    curl -s -X DELETE \
        "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/$RECORD_ID" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json" | jq '{success: .success}'

# Verify DNS resolution is working
dns-verify:
    @echo "Resolving {{domain}}..."
    @dig +short {{domain}} CNAME || true
    @echo ""
    @echo "HTTP check:"
    @curl -sI "https://{{domain}}" 2>/dev/null | head -5 || echo "Site not yet reachable"
    @echo ""
    @echo "TLS certificate subject:"
    @echo | openssl s_client -connect {{domain}}:443 -servername {{domain}} 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null || echo "Could not retrieve certificate"

# --- Hugo local development ---

# Install Hugo modules (run after cloning or updating theme)
docs-init:
    cd website && hugo mod get && hugo mod tidy

# Run Hugo dev server locally (with drafts and future posts)
docs-serve:
    cd website && hugo server --buildDrafts --buildFuture

# Build the Hugo site locally to website/public/
docs-build:
    cd website && hugo mod get && hugo --minify

# Clean Hugo build artifacts
docs-clean:
    rm -rf website/public website/resources website/.hugo_build.lock

# Create a new content page (usage: just docs-new docs/getting-started/new-page.md)
docs-new page:
    cd website && hugo new content {{page}}
