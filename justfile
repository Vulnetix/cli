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

# Build for all platforms using build.sh
build-all:
    @echo "Building for all platforms..."
    @VERSION={{version}} ./build.sh

# Build release binaries for all platforms
build-release: clean
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building release binaries for all platforms..."
    mkdir -p {{output_dir}}
    ldflags="{{ldflags}}"

    echo "Building for Linux AMD64..."
    GOOS=linux GOARCH=amd64 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-linux-amd64 .
    echo "Building for Linux ARM64..."
    GOOS=linux GOARCH=arm64 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-linux-arm64 .
    echo "Building for Linux ARM..."
    GOOS=linux GOARCH=arm go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-linux-arm .
    echo "Building for Linux 386..."
    GOOS=linux GOARCH=386 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-linux-386 .

    echo "Building for macOS AMD64..."
    GOOS=darwin GOARCH=amd64 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-darwin-amd64 .
    echo "Building for macOS ARM64..."
    GOOS=darwin GOARCH=arm64 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-darwin-arm64 .

    echo "Building for Windows AMD64..."
    GOOS=windows GOARCH=amd64 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-windows-amd64.exe .
    echo "Building for Windows ARM64..."
    GOOS=windows GOARCH=arm64 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-windows-arm64.exe .
    echo "Building for Windows ARM..."
    GOOS=windows GOARCH=arm go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-windows-arm.exe .
    echo "Building for Windows 386..."
    GOOS=windows GOARCH=386 go build -ldflags "$ldflags" -o {{output_dir}}/{{binary}}-windows-386.exe .

    echo "Built release binaries for all platforms"

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

# Coverage reporting
test-coverage:
    go test -v -cover ./...

# Coverage with HTML report
test-coverage-html:
    #!/usr/bin/env bash
    set -euo pipefail
    go test -v -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html

# Coverage threshold enforcement (90% minimum)
test-coverage-check:
    #!/usr/bin/env bash
    set -euo pipefail
    go test -v -coverprofile=coverage.out ./...
    go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | awk '{if ($1 < 90) exit 1}'

# Comprehensive test suite
test-all: test test-coverage-check

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

# Update all package manager manifests (flake.nix, Homebrew, Scoop) to the latest release
update-packages VERSION="":
    #!/usr/bin/env bash
    set -euo pipefail

    # Determine version
    if [ -n "{{VERSION}}" ]; then
        VER="{{VERSION}}"
    else
        VER=$(gh release view --json tagName -q '.tagName' 2>/dev/null)
        if [ -z "$VER" ]; then
            echo "Error: could not determine latest release version"
            exit 1
        fi
    fi
    VER_NUM="${VER#v}"
    echo "Updating package manifests to v${VER_NUM}..."

    # Download checksums
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    gh release download "v${VER_NUM}" --pattern checksums.txt --dir "$TMPDIR"
    CHECKSUMS="$TMPDIR/checksums.txt"

    # Extract hashes
    hash_for() { grep "$1\$" "$CHECKSUMS" | awk '{print $1}'; }
    DARWIN_ARM64=$(hash_for vulnetix-darwin-arm64)
    DARWIN_AMD64=$(hash_for vulnetix-darwin-amd64)
    LINUX_ARM64=$(hash_for vulnetix-linux-arm64)
    LINUX_AMD64=$(hash_for vulnetix-linux-amd64)
    WIN_AMD64=$(hash_for vulnetix-windows-amd64.exe)
    WIN_386=$(hash_for vulnetix-windows-386.exe)
    WIN_ARM64=$(hash_for vulnetix-windows-arm64.exe)
    echo "Checksums extracted for 7 binaries"

    # --- flake.nix ---
    echo ""
    echo "==> Updating flake.nix..."
    sed -i "s/version = \"[^\"]*\";/version = \"${VER_NUM}\";/" flake.nix
    echo "    version → ${VER_NUM}"

    # --- Homebrew formula ---
    BREW="../homebrew-tap/Formula/vulnetix.rb"
    if [ -f "$BREW" ]; then
        echo ""
        echo "==> Updating Homebrew formula..."
        sed -i "s/version \"[^\"]*\"/version \"${VER_NUM}\"/" "$BREW"
        sed -i "/vulnetix-darwin-arm64/{n;s/sha256 \"[a-f0-9]*\"/sha256 \"${DARWIN_ARM64}\"/}" "$BREW"
        sed -i "/vulnetix-darwin-amd64/{n;s/sha256 \"[a-f0-9]*\"/sha256 \"${DARWIN_AMD64}\"/}" "$BREW"
        sed -i "/vulnetix-linux-arm64/{n;s/sha256 \"[a-f0-9]*\"/sha256 \"${LINUX_ARM64}\"/}" "$BREW"
        sed -i "/vulnetix-linux-amd64/{n;s/sha256 \"[a-f0-9]*\"/sha256 \"${LINUX_AMD64}\"/}" "$BREW"
        echo "    vulnetix.rb → ${VER_NUM}"
    else
        echo "Warning: Homebrew formula not found at $BREW"
    fi

    # --- Scoop manifest ---
    SCOOP="../scoop-bucket/bucket/vulnetix.json"
    if [ -f "$SCOOP" ]; then
        echo ""
        echo "==> Updating Scoop manifest..."
        jq --indent 4 \
           --arg v "$VER_NUM" \
           --arg h64 "$WIN_AMD64" \
           --arg h32 "$WIN_386" \
           --arg harm "$WIN_ARM64" \
           '.version = $v |
            .architecture."64bit".url = "https://github.com/Vulnetix/cli/releases/download/v\($v)/vulnetix-windows-amd64.exe#/vulnetix.exe" |
            .architecture."64bit".hash = $h64 |
            .architecture."32bit".url = "https://github.com/Vulnetix/cli/releases/download/v\($v)/vulnetix-windows-386.exe#/vulnetix.exe" |
            .architecture."32bit".hash = $h32 |
            .architecture.arm64.url = "https://github.com/Vulnetix/cli/releases/download/v\($v)/vulnetix-windows-arm64.exe#/vulnetix.exe" |
            .architecture.arm64.hash = $harm' "$SCOOP" > "$TMPDIR/vulnetix.json"
        mv "$TMPDIR/vulnetix.json" "$SCOOP"
        echo "    vulnetix.json → ${VER_NUM}"
    else
        echo "Warning: Scoop manifest not found at $SCOOP"
    fi

    # --- Commit and push ---
    echo ""
    echo "==> Committing and pushing..."

    # CLI repo (flake.nix)
    git add flake.nix
    if ! git diff --cached --quiet; then
        git commit -m "chore: update flake.nix to v${VER_NUM}"
        git push
        echo "    cli: pushed"
    else
        echo "    cli: no changes"
    fi

    # Homebrew tap
    if [ -f "$BREW" ]; then
        git -C ../homebrew-tap add Formula/vulnetix.rb
        if ! git -C ../homebrew-tap diff --cached --quiet; then
            git -C ../homebrew-tap commit -m "vulnetix ${VER_NUM}"
            git -C ../homebrew-tap push
            echo "    homebrew-tap: pushed"
        else
            echo "    homebrew-tap: no changes"
        fi
    fi

    # Scoop bucket
    if [ -f "$SCOOP" ]; then
        git -C ../scoop-bucket add bucket/vulnetix.json
        if ! git -C ../scoop-bucket diff --cached --quiet; then
            git -C ../scoop-bucket commit -m "vulnetix ${VER_NUM}"
            git -C ../scoop-bucket push
            echo "    scoop-bucket: pushed"
        else
            echo "    scoop-bucket: no changes"
        fi
    fi

    echo ""
    echo "Done. All package manifests updated to v${VER_NUM}."

# --- Local CI ---

# Run GitHub Actions workflows locally with act (defaults to test workflow)
act workflow="test" *args="":
    act -W .github/workflows/{{workflow}}.yml --container-daemon-socket unix://$XDG_RUNTIME_DIR/podman/podman.sock -s GITHUB_TOKEN="$(gh auth token)" {{args}}

# --- Hugo local development ---

# One-command local dev: install modules and start dev server with live reload
docs-dev:
    #!/usr/bin/env bash
    set -euo pipefail
    cd website
    echo "Installing Hugo modules..."
    hugo mod get && hugo mod tidy
    echo ""
    echo "Starting dev server at http://localhost:1313"
    hugo server --buildDrafts --buildFuture --navigateToChanged

# Install Hugo modules (run after cloning or updating theme)
docs-init:
    cd website && hugo mod get && hugo mod tidy

# Run Hugo dev server locally (with drafts and future posts)
docs-serve:
    cd website && hugo server --buildDrafts --buildFuture

# Build the Hugo site locally to website/public/
docs-build:
    cd website && hugo mod get && hugo --minify

# Preview production build locally
docs-preview: docs-build
    #!/usr/bin/env bash
    set -euo pipefail
    cd website
    echo "Serving production build at http://localhost:1313"
    hugo server --minify --disableLiveReload

# Clean Hugo build artifacts
docs-clean:
    rm -rf website/public website/resources website/.hugo_build.lock

# Create a new content page (usage: just docs-new docs/getting-started/new-page.md)
docs-new page:
    cd website && hugo new content {{page}}
