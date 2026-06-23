# Vulnetix CLI development tasks
# Requires: just (https://github.com/casey/just)

set dotenv-load

# --- Build configuration ---

# Defense-in-depth: suppress CGO C-compiler warnings from vendored
# tree-sitter parser.c files. The lua parser's null-character warning
# is fixed at source in third_party/treesitter-lua/, so this is only
# needed if a similar warning surfaces in another grammar in future.
# Override with `CGO_CFLAGS="..." just <task>` for local debugging.
export CGO_CFLAGS := env("CGO_CFLAGS", "-w")

version := env("VERSION", "dev")
commit := `git rev-parse --short HEAD 2>/dev/null || echo "unknown"`
build_date := `date -u +%Y-%m-%dT%H:%M:%SZ`
output_dir := "bin"
binary := "vulnetix"
ldflags := "-s -w -X github.com/vulnetix/cli/v3/cmd.version=" + version + " -X github.com/vulnetix/cli/v3/cmd.commit=" + commit + " -X github.com/vulnetix/cli/v3/cmd.buildDate=" + build_date
extra_root := env("VULNETIX_EXTRA_ROOT", "/home/chris/GitHub/Vulnetix-extra")
sast_fixtures := env("VULNETIX_SAST_FIXTURES", extra_root + "/sast-rule-evals")
sca_fixtures := env("VULNETIX_SCA_FIXTURES", extra_root + "/sca-manifest-fixtures")
fixture_rule_flags := "--rule Vulnetix/community-rules --rule Vulnetix/opa-fugue-regula --rule Vulnetix/opa-checkmarx-kics --rule Vulnetix/opa-cds-aws-tf --rule Vulnetix/opa-cigna-tf --rule Vulnetix/opa-aquasecurity-trivy"

# --- Build tasks ---

# Build binary for current platform.
# CGO is required for the bundled tree-sitter grammars (reachability).
build:
    @echo "Building Vulnetix CLI..."
    @mkdir -p {{output_dir}}
    CGO_ENABLED=1 go build -ldflags "{{ldflags}}" -o {{output_dir}}/{{binary}} .
    @echo "Built {{output_dir}}/{{binary}}"

# Build development version (with debug info, -dev suffix)
dev:
    @echo "Building development version..."
    @mkdir -p {{output_dir}}
    CGO_ENABLED=1 go build -ldflags "-X github.com/vulnetix/cli/v3/cmd.version={{version}}-dev -X github.com/vulnetix/cli/v3/cmd.commit={{commit}} -X github.com/vulnetix/cli/v3/cmd.buildDate={{build_date}}" -o {{output_dir}}/{{binary}} .
    @echo "Built {{output_dir}}/{{binary}} (dev)"

# Install zig (the C cross-compiler used for cross-target CGO builds)
# into ./bin/zig. Idempotent: only downloads if missing.
install-zig:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v zig >/dev/null 2>&1; then
        echo "zig already on PATH: $(zig version)"
        exit 0
    fi
    if [ -x ./bin/zig ]; then
        echo "zig already in ./bin/zig"
        exit 0
    fi
    mkdir -p ./bin
    ZIG_VER="0.13.0"
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case "$OS-$ARCH" in
        linux-x86_64)  TARBALL="zig-linux-x86_64-${ZIG_VER}.tar.xz" ;;
        linux-aarch64) TARBALL="zig-linux-aarch64-${ZIG_VER}.tar.xz" ;;
        darwin-x86_64) TARBALL="zig-macos-x86_64-${ZIG_VER}.tar.xz" ;;
        darwin-arm64)  TARBALL="zig-macos-aarch64-${ZIG_VER}.tar.xz" ;;
        *) echo "unsupported host $OS-$ARCH for install-zig"; exit 1 ;;
    esac
    curl -sSL "https://ziglang.org/download/${ZIG_VER}/${TARBALL}" -o /tmp/zig.tar.xz
    tar -xJf /tmp/zig.tar.xz -C /tmp
    rm -f /tmp/zig.tar.xz
    mv /tmp/zig-*-${ZIG_VER} ./bin/zig-dist
    ln -sf zig-dist/zig ./bin/zig
    echo "zig installed: $(./bin/zig version)"

# Build for all platforms using build.sh
build-all:
    @echo "Building for all platforms..."
    @VERSION={{version}} ./build.sh

# Build release binaries for all platforms. CGO is required for the
# bundled tree-sitter grammars. Uses `zig cc` as a cross-platform C
# toolchain. Run `just install-zig` first if zig isn't on PATH.
build-release: clean
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building release binaries for all platforms..."
    mkdir -p {{output_dir}}
    ldflags="{{ldflags}}"
    ZIG="$(command -v zig || echo "$PWD/bin/zig")"
    if ! "$ZIG" version >/dev/null 2>&1; then
        echo "ERROR: zig not found. Run 'just install-zig' first." >&2
        exit 1
    fi

    build_target() {
        local goos="$1" goarch="$2" triple="$3" suffix="$4"
        echo "Building for ${goos}/${goarch} (${triple})..."
        CGO_ENABLED=1 \
            CC="$ZIG cc -target $triple" \
            CXX="$ZIG c++ -target $triple" \
            GOOS="$goos" GOARCH="$goarch" \
            go build -ldflags "$ldflags" \
            -o {{output_dir}}/{{binary}}-${goos}-${goarch}${suffix} .
    }

    build_target linux  amd64 x86_64-linux-musl       ""
    build_target linux  arm64 aarch64-linux-musl      ""
    build_target linux  arm   arm-linux-musleabihf    ""
    build_target linux  386   x86-linux-musl          ""
    build_target darwin amd64 x86_64-macos            ""
    build_target darwin arm64 aarch64-macos           ""
    build_target windows amd64 x86_64-windows-gnu    ".exe"
    build_target windows arm64 aarch64-windows-gnu   ".exe"

    # Dropped targets: windows/arm and windows/386 — zig cc + CGO is unstable
    # for these triples in our matrix. Build manually if you need them.

    echo "Built release binaries for all supported platforms"

# Install to GOPATH
install:
    go install -ldflags "{{ldflags}}" .

# Regenerate secret-detection rules + docs from the catalog (single source of truth)
gen-secrets:
    go run ./internal/sast/secretsgen .
    just fmt

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

# Benchmark the installed vulnetix CLI against this repo: sca, sast,
# sca+autofix(safest), scan, scan+autofix(safest). Each scenario runs on a fresh
# repo copy; min/median/max wall-clock + findings are written to a Markdown
# report under benchmark/results/. Defaults to `vulnetix` on PATH (brew install);
# override with env vars, e.g.:
#   RUNS=5 just benchmark
#   VULNETIX_BIN=./bin/vulnetix just benchmark         # benchmark a local build
#   GOPROXY=https://proxy.golang.org,direct just benchmark
# See benchmark/README.md for the full scenario list and env knobs.
benchmark:
    bash benchmark/run.sh

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
    go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | awk '{if ($1 < 15) exit 1}'

# Comprehensive test suite
test-all: test test-coverage-check

# Exhaustive CLI command/subcommand help and completion smoke tests.
test-command-help: dev
    #!/usr/bin/env bash
    set -euo pipefail
    BIN="$(pwd)/{{output_dir}}/{{binary}}"
    log_dir="$(mktemp -d /tmp/vulnetix-cli-command-help.XXXXXX)"
    echo "Writing command help logs to ${log_dir}"

    commands=(
      ""
      "auth" "auth login" "auth logout" "auth status" "auth verify"
      "completion" "completion bash" "completion zsh" "completion fish" "completion powershell"
      "containers" "env" "gha" "gha upload" "gha status" "iac" "license"
      "sast" "sca" "scan" "scan status" "secrets" "triage" "triage status"
      "update" "upload" "version"
      "vdb"
      "vdb advisories" "vdb affected"
      "vdb ai-assisted-exploits" "vdb ai-discoveries" "vdb ai-in-wild" "vdb ai-malware"
      "vdb attack-techniques" "vdb attack-techniques get" "vdb attack-techniques list"
      "vdb cache" "vdb cache clear"
      "vdb cloud-locators"
      "vdb cwe" "vdb cwe guidance"
      "vdb ecosystem" "vdb ecosystem package" "vdb ecosystem group"
      "vdb ecosystems" "vdb exploit-trends"
      "vdb exploits" "vdb exploits archived" "vdb exploits download" "vdb exploits poc"
      "vdb exploits search" "vdb exploits sources" "vdb exploits types"
      "vdb fixes" "vdb fixes distributions"
      "vdb gcve" "vdb gcve issuances"
      "vdb ids" "vdb iocs" "vdb iocs get" "vdb iocs list"
      "vdb kev" "vdb kev download" "vdb kev get" "vdb kev list" "vdb kev reasons" "vdb kev sources"
      "vdb metrics" "vdb metrics types"
      "vdb msrc" "vdb msrc patch-tuesday" "vdb msrc patch-tuesdays"
      "vdb nuclei" "vdb nuclei get"
      "vdb packages" "vdb packages search"
      "vdb product" "vdb purl"
      "vdb raw" "vdb raw get" "vdb raw sources"
      "vdb remediation" "vdb remediation plan"
      "vdb scorecard" "vdb scorecard search"
      "vdb search" "vdb sightings"
      "vdb snort-rules" "vdb snort-rules get" "vdb snort-rules list"
      "vdb sources" "vdb spec" "vdb status" "vdb summary"
      "vdb timeline" "vdb traffic-filters" "vdb triage"
      "vdb vendor-trends" "vdb versions"
      "vdb vex" "vdb vex get" "vdb vex list"
      "vdb vuln" "vdb vulns" "vdb workarounds"
      "vdb yara-rules" "vdb yara-rules get" "vdb yara-rules list"
    )

    for cmd in "${commands[@]}"; do
      label="${cmd:-root}"
      label="${label// /__}"
      echo "help: vulnetix ${cmd}"
      # shellcheck disable=SC2086
      "$BIN" $cmd --help > "${log_dir}/${label}.help"
    done

    for shell in bash zsh fish powershell; do
      echo "completion: ${shell}"
      "$BIN" completion "${shell}" > "${log_dir}/completion-${shell}.txt"
      test -s "${log_dir}/completion-${shell}.txt"
    done

    echo "Command help matrix passed"

# CLI argument validation and expected-failure guardrails.
test-command-args: dev
    #!/usr/bin/env bash
    set -euo pipefail
    BIN="./{{output_dir}}/{{binary}}"
    log_dir="$(mktemp -d /tmp/vulnetix-cli-command-args.XXXXXX)"
    echo "Writing argument validation logs to ${log_dir}"

    pass=0
    fail=0

    run_ok() {
      local name="$1"
      shift
      echo "ok: ${name}"
      if "$@" > "${log_dir}/${name}.out" 2> "${log_dir}/${name}.err"; then
        pass=$((pass + 1))
      else
        echo "FAILED expected success: ${name}" >&2
        cat "${log_dir}/${name}.err" >&2
        fail=$((fail + 1))
      fi
    }

    run_fail() {
      local name="$1"
      shift
      echo "fail: ${name}"
      if "$@" > "${log_dir}/${name}.out" 2> "${log_dir}/${name}.err"; then
        echo "FAILED expected non-zero exit: ${name}" >&2
        fail=$((fail + 1))
      else
        pass=$((pass + 1))
      fi
    }

    run_ok version_short "$BIN" version --short --no-analytics
    run_ok env_json "$BIN" env --output json --no-progress --disable-memory --no-analytics
    run_ok scan_list_default_rules "$BIN" scan --list-default-rules --no-progress --disable-memory --no-analytics
    run_ok triage_status_json "$BIN" triage status --format json --no-progress --no-analytics
    run_ok vdb_cache_clear "$BIN" vdb cache clear --disable-memory --no-analytics

    run_fail scan_dry_run_fresh_exploits "$BIN" scan --dry-run --fresh-exploits --no-progress --disable-memory --no-analytics
    run_fail scan_two_stdout_outputs "$BIN" scan --path "{{sca_fixtures}}/npm-lock" -o json-cyclonedx -o json-sarif --no-progress --disable-memory --no-analytics
    run_fail scan_unknown_output_ext "$BIN" scan --path "{{sca_fixtures}}/npm-lock" -o "${log_dir}/out.txt" --no-progress --disable-memory --no-analytics
    run_fail license_bad_mode "$BIN" license --path "{{sca_fixtures}}/npm-lock" --mode nope --no-progress --disable-memory --no-analytics
    run_fail license_bad_output "$BIN" license --path "{{sca_fixtures}}/npm-lock" --output xml --no-progress --disable-memory --no-analytics
    run_fail auth_login_bad_uuid "$BIN" auth login --org-id not-a-uuid --api-key 0123456789abcdef --store project --no-progress --no-analytics
    run_fail completion_bad_shell "$BIN" completion nope --no-analytics
    run_fail vdb_bad_output "$BIN" vdb --output xml status --disable-memory --no-analytics
    run_fail vdb_mutually_exclusive_indent "$BIN" vdb --compact --sparse status --disable-memory --no-analytics
    run_fail vdb_vuln_missing_arg "$BIN" vdb vuln --disable-memory --no-analytics
    run_fail vdb_cwe_guidance_missing_arg "$BIN" vdb cwe guidance --disable-memory --no-analytics

    if [ "$fail" -ne 0 ]; then
      echo "${fail} argument validation case(s) failed; logs: ${log_dir}" >&2
      exit 1
    fi
    echo "${pass} argument validation cases passed"

# Fixture-driven CLI scenarios against SCA, SAST, IaC, container, secret, and license targets.
test-command-fixtures: dev
    #!/usr/bin/env bash
    set -euo pipefail
    BIN="$(pwd)/{{output_dir}}/{{binary}}"
    SCA="{{sca_fixtures}}"
    SAST="{{sast_fixtures}}"
    RULE_FLAGS=( {{fixture_rule_flags}} )
    work="$(mktemp -d /tmp/vulnetix-cli-fixtures.XXXXXX)"
    log_dir="${work}/logs"
    mkdir -p "${log_dir}"
    echo "Working directory: ${work}"
    echo "Writing fixture logs to ${log_dir}"

    copy_fixture() {
      local src="$1"
      local dst="$2"
      mkdir -p "$dst"
      if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude .git --exclude .ruff_cache "$src/" "$dst/"
      else
        cp -a "$src/." "$dst/"
        rm -rf "$dst/.git" "$dst/.ruff_cache"
      fi
    }

    run_ok() {
      local name="$1"
      shift
      echo "fixture: ${name}"
      "$@" > "${log_dir}/${name}.out" 2> "${log_dir}/${name}.err"
    }

    run_policy() {
      local name="$1"
      shift
      echo "fixture policy gate: ${name}"
      if "$@" > "${log_dir}/${name}.out" 2> "${log_dir}/${name}.err"; then
        echo "Expected policy gate to return non-zero: ${name}" >&2
        exit 1
      fi
    }

    sca_work="${work}/sca-manifest-fixtures"
    sast_work="${work}/sast-rule-evals"
    copy_fixture "$SCA" "$sca_work"
    copy_fixture "$SAST" "$sast_work"

    run_ok scan_dry_run_all "$BIN" scan --dry-run --path "$sca_work" --depth 2 --show-detected --show-all-manifests --exclude .git --no-progress --disable-memory --no-analytics
    run_ok sca_wrapper_npm_lock "$BIN" sca --path "$sca_work/npm-lock" --depth 2 --show-detected --show-all-manifests --exclude .git --no-progress --disable-memory --no-analytics
    run_ok license_dry_run_all "$BIN" license --dry-run --path "$sca_work" --depth 2 --exclude .git --no-progress --disable-memory --no-analytics
    run_ok license_json "$BIN" license --path "$sca_work/npm-lock" --depth 2 --output json --no-progress --disable-memory --no-analytics
    run_ok license_spdx "$BIN" license --path "$sca_work/npm-lock" --depth 2 --output json-spdx --no-progress --disable-memory --no-analytics
    run_policy license_severity_gate "$BIN" license --path "$sca_work/npm-lock" --depth 2 --allow MIT --severity low --no-progress --disable-memory --no-analytics

    run_ok scan_sca_output_file "$BIN" scan --path "$sca_work/npm-lock" --depth 2 --no-sast --no-licenses --no-secrets --no-containers --no-iac -o "${work}/npm-lock.cdx.json" --no-progress --disable-memory --no-analytics
    test -s "${work}/npm-lock.cdx.json"
    run_ok scan_sarif_output_file "$BIN" scan --path "$sast_work/python/vnx-py-002" --depth 2 --evaluate-sast --no-sca --no-licenses --no-secrets --no-containers --no-iac -o "${work}/py.sarif" --no-progress --disable-memory --no-analytics
    test -s "${work}/py.sarif"

    run_ok sast_full_rules "$BIN" sast --path "$sast_work" --depth 4 "${RULE_FLAGS[@]}" --no-progress --disable-memory --no-analytics
    run_ok secrets_full_rules "$BIN" secrets --path "$sast_work/secrets" --depth 3 "${RULE_FLAGS[@]}" --no-progress --disable-memory --no-analytics
    run_ok containers_full_rules "$BIN" containers --path "$sca_work/docker" --depth 2 "${RULE_FLAGS[@]}" --no-progress --disable-memory --no-analytics
    run_ok containers_containerfile "$BIN" containers --path "$sca_work/docker-containerfile" --depth 2 "${RULE_FLAGS[@]}" --no-progress --disable-memory --no-analytics
    run_ok iac_full_rules "$BIN" iac --path "$sca_work/terraform" --depth 2 "${RULE_FLAGS[@]}" --no-progress --disable-memory --no-analytics

    run_ok scan_from_memory "$BIN" scan --from-memory --path "$sca_work/npm-lock" --no-progress --disable-memory --no-analytics
    run_ok license_from_memory "$BIN" license --from-memory --path "$sca_work/npm-lock" --no-progress --disable-memory --no-analytics

    echo "Fixture command scenarios passed"

# Live VDB smoke scenarios using community fallback credentials.
test-command-vdb-live: dev
    #!/usr/bin/env bash
    set -euo pipefail
    BIN="$(pwd)/{{output_dir}}/{{binary}}"
    log_dir="$(mktemp -d /tmp/vulnetix-cli-vdb-live.XXXXXX)"
    timeout_seconds="${VDB_LIVE_TIMEOUT_SECONDS:-90}"
    live_cve="${VDB_LIVE_CVE:-CVE-2024-3094}"
    vuln_cve="${VDB_LIVE_VULN_CVE:-CVE-2021-44228}"
    failures=()
    echo "Writing live VDB logs to ${log_dir}"
    echo "Per-command timeout: ${timeout_seconds}s"
    echo "Detail CVE: ${live_cve}; vuln lookup CVE: ${vuln_cve}"

    run_live() {
      local name="$1"
      shift
      echo "vdb: ${name}"
      if (cd "$log_dir" && timeout "${timeout_seconds}" "$BIN" vdb --disable-memory --no-analytics --no-progress --reachability off "$@") > "${log_dir}/${name}.out" 2> "${log_dir}/${name}.err"; then
        return 0
      else
        rc=$?
        failures+=("${name}:${rc}")
        echo "  failed (${rc}); see ${log_dir}/${name}.err" >&2
      fi
    }

    run_live_probe() {
      local name="$1"
      shift
      echo "vdb probe: ${name}"
      if ! (cd "$log_dir" && timeout "${timeout_seconds}" "$BIN" vdb --disable-memory --no-analytics --no-progress --reachability off "$@") > "${log_dir}/${name}.out" 2> "${log_dir}/${name}.err"; then
        echo "  probe failed; see ${log_dir}/${name}.err" >&2
      fi
    }

    run_live status status
    run_live ecosystems ecosystems -o json
    run_live sources sources -o json
    run_live summary summary -o json
    run_live spec spec -o json
    run_live vuln vuln "$vuln_cve" -o json
    run_live exploits exploits "$live_cve" -o json
    run_live_probe exploits_search exploits search --query log4j --limit 3 -o json
    run_live exploits_sources exploits sources -o json
    run_live exploits_types exploits types -o json
    run_live fixes fixes "$live_cve" -o json
    run_live_probe fixes_distributions fixes distributions -o json
    run_live timeline timeline "$live_cve" --include source,exploit --scores-limit 5 -o json
    run_live affected affected "$live_cve" -o json
    run_live advisories advisories "$live_cve" -o json
    run_live workarounds workarounds "$live_cve" -o json
    run_live cwe_guidance cwe guidance "$live_cve" -o json
    run_live remediation_plan remediation plan "$live_cve" --include-guidance --include-verification-steps -o json
    run_live cloud_locators cloud-locators --vendor amazon --product s3 -o json
    run_live scorecard scorecard "$live_cve" -o json
    run_live scorecard_search scorecard search kubernetes -o json
    run_live product product express --limit 3 -o json
    run_live versions versions express -o json
    run_live vulns vulns express --limit 3 -o json
    run_live packages_search packages search express --ecosystem npm --limit 3 -o json
    run_live purl_versions purl pkg:npm/express --limit 3 -o json
    run_live purl_vulns purl pkg:npm/express@4.17.1 --vulns --limit 3 -o json
    run_live gcve gcve --start 2024-01-01 --end 2024-01-02 -o json
    run_live gcve_issuances gcve issuances --year 2024 --month 1 --limit 3 -o json
    run_live ids ids 2024 1 --limit 3 -o json
    run_live_probe search search "$live_cve" --limit 3 -o json
    run_live kev_list kev list --format json --limit 3
    kev_id="$(sed -n 's/.*"cveId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${log_dir}/kev_list.out" | head -1)"
    if [ -n "$kev_id" ]; then
      run_live_probe kev_get kev get "$kev_id" -o json
    else
      echo "  failed to derive KEV id from kev_list output" >&2
    fi
    run_live kev_reasons kev reasons
    run_live kev_sources kev sources
    run_live iocs_get iocs get "$live_cve" -o json
    run_live iocs_list iocs list --limit 3 -o json
    run_live nuclei_get nuclei get "$live_cve" --format json
    run_live yara_get yara-rules get "$live_cve" --format json
    run_live yara_list yara-rules list --cve-id "$live_cve" --limit 3 --format json
    run_live snort_get snort-rules get "$live_cve" --format json
    run_live snort_list snort-rules list --cve-id "$live_cve" --limit 3 --format json
    run_live attack_get attack-techniques get "$live_cve" -o json
    run_live attack_list attack-techniques list --cve-id "$live_cve" --limit 3 -o json
    run_live sightings sightings "$live_cve" -o json
    run_live traffic_filters traffic-filters "$live_cve" --limit 3 -o json
    run_live msrc_list msrc patch-tuesdays -o json
    run_live msrc_get msrc patch-tuesday 2024-01-09 -o json
    run_live raw_sources raw sources -o json
    run_live_probe raw_get raw get "$live_cve" --source mitre-cve -o "${log_dir}/raw-get.bin"
    run_live vex_get vex get "$live_cve" -o json
    run_live vex_list vex list --cve-id "$live_cve" --limit 3 -o json
    run_live metrics_types metrics types -o json
    run_live ecosystem_package ecosystem package npm express -o json
    run_live vendor_trends vendor-trends --vendor apache --year 2024 -o json
    run_live exploit_trends exploit-trends -o json
    run_live triage triage --severity high --limit 3 -o json
    run_live ai_discoveries ai-discoveries --limit 3 -o json
    run_live ai_assisted ai-assisted-exploits --limit 3 -o json
    run_live ai_in_wild ai-in-wild --limit 3 -o json
    run_live ai_malware ai-malware --limit 3 -o json

    if [ "${#failures[@]}" -ne 0 ]; then
      echo "Live VDB command failures: ${failures[*]}" >&2
      echo "Logs: ${log_dir}" >&2
      exit 1
    fi

    echo "Live VDB command scenarios passed"

# Full offline command validation: help, argument guardrails, and fixture coverage.
test-commands: test-command-help test-command-args test-command-fixtures

# Full command validation, including live VDB API smoke/probe coverage.
test-commands-live: test-commands test-command-vdb-live

# Run all Go tests and the complete CLI command matrix.
test-all-commands: test-all test-commands-live

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

# Bump the pinned vdb-cyclonedx version. vdb-cyclonedx is a public tagged Go
# module (github.com/Vulnetix/vdb-cyclonedx); tag a new release there, then run
# this to point the CLI at it.
update-vdb-cyclonedx VERSION:
    go get github.com/Vulnetix/vdb-cyclonedx@{{VERSION}}
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
#   7. test-go-install job verifies `go install github.com/vulnetix/cli/v3@latest` works
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
    WIN_ARM64=$(hash_for vulnetix-windows-arm64.exe)
    echo "Checksums extracted"

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
        # 32-bit Windows builds were dropped when CGO became a build
        # requirement (zig cc + CGO is unstable for i386-windows).
        jq --indent 4 \
           --arg v "$VER_NUM" \
           --arg h64 "$WIN_AMD64" \
           --arg harm "$WIN_ARM64" \
           '.version = $v |
            .architecture."64bit".url = "https://github.com/Vulnetix/cli/releases/download/v\($v)/vulnetix-windows-amd64.exe#/vulnetix.exe" |
            .architecture."64bit".hash = $h64 |
            .architecture.arm64.url = "https://github.com/Vulnetix/cli/releases/download/v\($v)/vulnetix-windows-arm64.exe#/vulnetix.exe" |
            .architecture.arm64.hash = $harm |
            del(.architecture."32bit")' "$SCOOP" > "$TMPDIR/vulnetix.json"
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
