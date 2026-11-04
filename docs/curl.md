# Binary Download

This documentation has moved to **[docs.vulnetix.com/cli/get-started/install](https://docs.vulnetix.com/cli/get-started/install/)**.

## Install script

```bash
curl -fsSL https://cli.vulnetix.com/install.sh | sh
```

The script installs the binary only when its SHA-256 matches the release's `checksums.txt`. It
stops when it has no SHA-256 tool, cannot fetch `checksums.txt`, or finds no entry for the
binary. When `cosign` is on `PATH` it also verifies the release's signed SLSA provenance
(`provenance.sigstore.json`) for the downloaded binary, and stops if that fails.

| Flag | Environment variable | Effect |
|---|---|---|
| `--require-provenance` | `VULNETIX_REQUIRE_PROVENANCE=1` | Fail unless `cosign` is on `PATH` and the provenance verifies |
| `--insecure-skip-verify` | `VULNETIX_INSECURE_SKIP_VERIFY=1` | Install without checking the checksum or the provenance, with a warning. Not recommended |

```bash
curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --require-provenance
```

`sh install.sh --help` lists every option. After a successful install the script sends one
anonymous GA4 event (OS, architecture, CLI version and a random id made for that install); set
`VULNETIX_NO_ANALYTICS=1` or `DO_NOT_TRACK=1` to opt out.

## Manual download

```bash
# Linux AMD64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix
./vulnetix auth login
```

```bash
# macOS (Apple Silicon)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-arm64 -o vulnetix
chmod +x vulnetix
./vulnetix auth login
```

```powershell
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.exe" -OutFile "vulnetix.exe"
.\vulnetix.exe auth login
```

All binaries are available at [GitHub Releases](https://github.com/Vulnetix/cli/releases/latest).

## Verify a manual download

Check the checksum, then the provenance, against the same release:

```bash
V=v4.17.1   # the release you downloaded
curl -fsSLO "https://github.com/Vulnetix/cli/releases/download/$V/checksums.txt"
curl -fsSLO "https://github.com/Vulnetix/cli/releases/download/$V/provenance.sigstore.json"
grep ' vulnetix-linux-amd64$' checksums.txt | sed 's/vulnetix-linux-amd64$/vulnetix/' | sha256sum -c -

cosign verify-blob-attestation \
  --bundle provenance.sigstore.json --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Vulnetix/cli/\.github/workflows/slsa-provenance\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+.*)$' \
  --certificate-github-workflow-repository Vulnetix/cli \
  vulnetix
```

The bundle is signed by the reusable workflow `.github/workflows/slsa-provenance.yml`, so the
certificate names that workflow rather than `release.yml`. Its subjects are every line of
`checksums.txt`, so one bundle covers every binary in the release.
