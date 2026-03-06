# Vulnetix CLI development tasks
# Requires: just (https://github.com/casey/just)

set dotenv-load

# --- Build configuration ---

version := env("VERSION", "dev")
commit := `git rev-parse --short HEAD 2>/dev/null || echo "unknown"`
build_date := `date -u +%Y-%m-%dT%H:%M:%SZ`
output_dir := "bin"
binary := "vulnetix"
ldflags := "-s -w -X github.com/vulnetix/cli/cmd.version=" + version + " -X github.com/vulnetix/cli/cmd.commit=" + commit + " -X github.com/vulnetix/cli/cmd.buildDate=" + build_date

# --- Build tasks ---

# Build binary for current platform
build:
    @echo "Building Vulnetix CLI..."
    @mkdir -p {{output_dir}}
    go build -ldflags "{{ldflags}}" -o {{output_dir}}/{{binary}} .
    @echo "Built {{output_dir}}/{{binary}}"

# Build development version (with debug info, -dev suffix)
dev:
    @echo "Building development version..."
    @mkdir -p {{output_dir}}
    go build -ldflags "-X github.com/vulnetix/cli/cmd.version={{version}}-dev -X github.com/vulnetix/cli/cmd.commit={{commit}} -X github.com/vulnetix/cli/cmd.buildDate={{build_date}}" -o {{output_dir}}/{{binary}} .
    @echo "Built {{output_dir}}/{{binary}} (dev)"

# Install to GOPATH
install:
    go install -ldflags "{{ldflags}}" .

# Run tests (updates statusline cache)
test:
    #!/usr/bin/env bash
    set -euo pipefail
    if go test -v ./...; then
        echo "pass" > /tmp/vulnetix-cli-test-cache
    else
        echo "fail" > /tmp/vulnetix-cli-test-cache
        exit 1
    fi

# Format code
fmt:
    go fmt ./...

# Lint code
lint:
    @if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else echo "golangci-lint not installed, using go vet..."; go vet ./...; fi

# Clean build artifacts
clean:
    rm -rf {{output_dir}}
    go clean

# Download and tidy dependencies
deps:
    go mod download
    go mod tidy

# Build and run with test UUID
run: build
    ./{{output_dir}}/{{binary}} --org-id "123e4567-e89b-12d3-a456-426614174000"

# --- Cloudflare DNS management for docs.cli.vulnetix.com (uses .env) ---

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

# --- Release flow ---
#
# Releases are fully automated via GitHub Actions using conventional commits.
#
# How it works:
#   1. Push to main with conventional commit messages
#   2. auto-version.yml analyzes commits since the last v* tag
#   3. Determines bump type from commit prefixes:
#        feat!: or BREAKING CHANGE: → major (v1.0.0 → v2.0.0)
#        feat:                      → minor (v1.0.0 → v1.1.0)
#        fix: chore: perf: etc.     → patch (v1.0.0 → v1.0.1)
#   4. Creates annotated tag (e.g. v1.1.0) and pushes it
#   5. Dispatches release.yml via workflow_dispatch
#   6. release.yml builds binaries for all platforms, generates checksums,
#      and publishes a GitHub Release with auto-generated release notes
#   7. test-go-install job verifies `go install github.com/vulnetix/cli@latest` works
#
# Manual release:
#   just release v1.2.3          — tag locally and push (triggers release.yml)
#   gh workflow run release.yml -f version=v1.2.3  — dispatch directly
#
# Useful commands:
#   just release-status          — show latest tag, unreleased commits, and pending bump
#   just release-dry-run         — preview what the next auto-version would produce
#

# Tag and push a release (triggers release.yml)
release tag:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! echo "{{tag}}" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "Error: tag must match vX.Y.Z (got '{{tag}}')"
        exit 1
    fi
    echo "Creating release {{tag}}..."
    git tag -a "{{tag}}" -m "Release {{tag}}"
    git push origin "{{tag}}"
    echo "Tag {{tag}} pushed. Release workflow will run automatically."
    echo "Watch: gh run watch \$(gh run list -w release.yml -L1 --json databaseId -q '.[0].databaseId')"

# Show release status: latest tag, unreleased commits, and pending bump type
release-status:
    #!/usr/bin/env bash
    set -euo pipefail
    LAST_TAG=$(git tag -l 'v*' --sort=-v:refname | head -n1)
    if [ -z "$LAST_TAG" ]; then
        echo "No version tags found. First release will be v0.0.1 (or higher)."
        LAST_TAG="v0.0.0"
        RANGE="HEAD"
    else
        echo "Latest release: $LAST_TAG"
        RANGE="${LAST_TAG}..HEAD"
    fi
    echo ""
    COMMITS=$(git log "$RANGE" --oneline 2>/dev/null)
    if [ -z "$COMMITS" ]; then
        echo "No unreleased commits."
        exit 0
    fi
    echo "Unreleased commits since $LAST_TAG:"
    echo "$COMMITS" | sed 's/^/  /'
    echo ""
    # Determine bump
    BUMP=""
    while IFS= read -r msg; do
        if echo "$msg" | grep -qE '^[a-z]+(\(.+\))?!:|BREAKING CHANGE:'; then
            BUMP="major"; break
        elif echo "$msg" | grep -qE '^feat(\(.+\))?:'; then
            [ "$BUMP" != "major" ] && BUMP="minor"
        elif echo "$msg" | grep -qE '^(fix|chore|perf|refactor|style|docs|test|build|ci)(\(.+\))?:'; then
            [ -z "$BUMP" ] && BUMP="patch"
        fi
    done < <(git log "$RANGE" --format="%s" 2>/dev/null)
    if [ -z "$BUMP" ]; then
        echo "Pending bump: none (no conventional commits found)"
    else
        CURRENT="${LAST_TAG#v}"
        IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"
        case "$BUMP" in
            major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
            minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
            patch) PATCH=$((PATCH + 1)) ;;
        esac
        echo "Pending bump: $BUMP → v${MAJOR}.${MINOR}.${PATCH}"
    fi

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
