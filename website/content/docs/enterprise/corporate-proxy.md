---
title: "Corporate Proxy"
weight: 1
description: "Configure Vulnetix CLI for corporate proxy servers, firewalls, and restricted networks."
---

Comprehensive guide for using Vulnetix CLI in corporate environments with proxy servers, firewalls, and restricted network access.

## Quick Start

```bash
# Set proxy environment variables
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,.company.com"

# Run Vulnetix
vulnetix --org-id "your-org-id-here"
```

## Proxy Configuration

### Basic HTTP/HTTPS Proxy

```bash
# Set proxy for current session
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,*.internal,.company.com"

# Make permanent by adding to shell profile
echo 'export HTTP_PROXY="http://proxy.company.com:8080"' >> ~/.bashrc
echo 'export HTTPS_PROXY="http://proxy.company.com:8080"' >> ~/.bashrc
echo 'export NO_PROXY="localhost,127.0.0.1,*.internal,.company.com"' >> ~/.bashrc
source ~/.bashrc
```

### Authenticated Proxy

```bash
# Basic authentication
export HTTP_PROXY="http://username:password@proxy.company.com:8080"
export HTTPS_PROXY="http://username:password@proxy.company.com:8080"

# URL-encode special characters in credentials
# Example: password with @ symbol
export HTTP_PROXY="http://user:p%40ssw0rd@proxy.company.com:8080"

# Use environment variables for credentials
export PROXY_USER="username"
export PROXY_PASS="password"
export HTTP_PROXY="http://${PROXY_USER}:${PROXY_PASS}@proxy.company.com:8080"
export HTTPS_PROXY="http://${PROXY_USER}:${PROXY_PASS}@proxy.company.com:8080"
```

### SOCKS Proxy

```bash
# SOCKS5 proxy
export ALL_PROXY="socks5://proxy.company.com:1080"
export all_proxy="socks5://proxy.company.com:1080"

# SOCKS5 with authentication
export ALL_PROXY="socks5://username:password@proxy.company.com:1080"

# SOCKS4 proxy
export ALL_PROXY="socks4://proxy.company.com:1080"
```

## Installation Behind Proxy

### Go Install with Proxy

```bash
# Configure Go proxy settings
go env -w GOPROXY="https://proxy.golang.org,direct"
go env -w GOSUMDB="sum.golang.org"

# For corporate proxies that intercept HTTPS
go env -w GOPROXY="direct"
go env -w GOSUMDB="off"

# Set proxy environment variables
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"

# Install Vulnetix
go install github.com/vulnetix/cli/v3@latest
```

### Binary Download with Proxy

```bash
# Using curl with proxy
curl -x http://proxy.company.com:8080 \
  -L https://github.com/vulnetix/cli/v3/releases/latest/download/vulnetix-linux-amd64 \
  -o vulnetix

# Using wget with proxy
wget -e use_proxy=yes \
  -e http_proxy=http://proxy.company.com:8080 \
  -e https_proxy=http://proxy.company.com:8080 \
  https://github.com/vulnetix/cli/v3/releases/latest/download/vulnetix-linux-amd64 \
  -O vulnetix

chmod +x vulnetix
```

## SSL/TLS Certificate Management

### Custom CA Certificates

```bash
# Add corporate CA certificate (Ubuntu/Debian)
sudo cp corporate-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Add corporate CA certificate (CentOS/RHEL)
sudo cp corporate-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust

# Add corporate CA certificate (macOS)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain corporate-ca.crt

# Set certificate bundle for applications
export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
export SSL_CERT_DIR="/etc/ssl/certs"
```

### Certificate Bundle Configuration

```bash
# Configure curl to use custom CA bundle
echo 'capath=/etc/ssl/certs/' >> ~/.curlrc
echo 'cacert=/etc/ssl/certs/ca-certificates.crt' >> ~/.curlrc

# Configure git to use custom CA bundle
git config --global http.sslCAInfo /etc/ssl/certs/ca-certificates.crt

# Disable SSL verification (not recommended for production)
export GIT_SSL_NO_VERIFY=true
export CURL_CA_BUNDLE=""
```

### Self-Signed Certificates

```bash
# Skip certificate verification (development only)
export CURL_INSECURE=true

# Add self-signed certificate to trust store
openssl s_client -connect api.vdb.vulnetix.com:443 -showcerts < /dev/null 2>/dev/null | \
  openssl x509 -outform PEM > vulnetix-cert.pem
sudo cp vulnetix-cert.pem /usr/local/share/ca-certificates/vulnetix.crt
sudo update-ca-certificates
```

## Network Configuration

### DNS Configuration

```bash
# Custom DNS servers
echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf.custom
echo 'nameserver 8.8.4.4' | sudo tee -a /etc/resolv.conf.custom

# Use custom DNS for specific domains
echo '10.0.0.1 app.vulnetix.company.com' | sudo tee -a /etc/hosts

# Configure systemd-resolved
sudo tee /etc/systemd/resolved.conf << EOF
[Resolve]
DNS=8.8.8.8 8.8.4.4
Domains=company.com
EOF
sudo systemctl restart systemd-resolved
```

### Firewall Rules

```bash
# Allow outbound HTTPS (port 443) for Vulnetix API
sudo ufw allow out 443/tcp

# Allow outbound HTTP (port 80) for package downloads
sudo ufw allow out 80/tcp

# Allow specific IP ranges
sudo ufw allow out to 203.0.113.0/24 port 443 proto tcp

# Check current firewall rules
sudo ufw status verbose
```

### Network Testing

```bash
# Test connectivity to the VDB API
curl -I https://api.vdb.vulnetix.com/health

# Test with proxy
curl -x http://proxy.company.com:8080 -I https://api.vdb.vulnetix.com/health

# Test DNS resolution
nslookup api.vdb.vulnetix.com
dig api.vdb.vulnetix.com

# Test specific ports
nc -zv api.vdb.vulnetix.com 443
telnet api.vdb.vulnetix.com 443
```

{{< callout type="info" >}}
The CLI reaches three Vulnetix hosts. A proxy allowlist that omits any of them
will break the corresponding feature:

| Host | Used by |
|------|---------|
| `api.vdb.vulnetix.com` | `scan`, `vdb`, `upload`, `gha`, `auth verify` |
| `www.vulnetix.com` | `auth login` (browser device flow) |
| `packages.vulnetix.com` | Package Firewall proxy |
{{< /callout >}}

## What the CLI Actually Reads

{{< callout type="warning" >}}
The CLI has **no proxy configuration of its own**. There is no `~/.vulnetix/config.yaml`, no `VULNETIX_HTTP_PROXY`, and no `--proxy`, `--timeout`, `--retries`, or `--skip-tls-verify` flag. Proxy and TLS behaviour comes entirely from Go's standard environment variables, which the sections above cover.
{{< /callout >}}

These are the only environment variables the CLI reads that matter in a restricted network:

| Variable | Read by | Purpose |
|----------|---------|---------|
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Go's HTTP transport | Route API calls through the proxy |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Go's TLS stack (Linux, BSD) | Trust a corporate root CA |
| `VULNETIX_API_URL` | `vulnetix scan` | Override the VDB API base URL |
| `VULNETIX_ORG_ID`, `VULNETIX_API_KEY` | all commands | Credentials |
| `GOPROXY`, `GOPRIVATE`, `GONOSUMDB` | `go install` | Only when installing via Go |

Everything else is standard: `curl` honours `HTTP_PROXY` when downloading the install script, and `git` needs its own `http.proxy` setting.

### Verbosity, Not a Log Level

There is no `VULNETIX_LOG_LEVEL` or `VULNETIX_DEBUG`. Use the flag:

```bash
vulnetix --verbose scan
```

### Timeouts Are Fixed

The VDB client uses a 30-second per-request timeout and pooled connections. It is not configurable from the command line. If a proxy is slow enough to trip that, fix the proxy.

### TLS Verification Cannot Be Disabled

There is deliberately no `--skip-tls-verify`. To trust an internal CA, add it to the system trust store (or `SSL_CERT_FILE`), as shown in [Custom CA Certificates](#custom-ca-certificates). Disabling verification would make the credential you are sending interceptable.

## CI/CD Integration with Proxy

### GitHub Actions

```yaml
name: Corporate Proxy Assessment

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: self-hosted  # Use self-hosted runner behind proxy
    env:
      HTTP_PROXY: ${{ secrets.CORPORATE_HTTP_PROXY }}
      HTTPS_PROXY: ${{ secrets.CORPORATE_HTTPS_PROXY }}
      NO_PROXY: ${{ secrets.CORPORATE_NO_PROXY }}
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure proxy for git
        run: |
          git config --global http.proxy $HTTP_PROXY
          git config --global https.proxy $HTTPS_PROXY

      - name: Run Vulnetix
        uses: vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
        env:
          HTTP_PROXY: ${{ secrets.CORPORATE_HTTP_PROXY }}
          HTTPS_PROXY: ${{ secrets.CORPORATE_HTTPS_PROXY }}
```

### GitLab CI

```yaml
# .gitlab-ci.yml
variables:
  HTTP_PROXY: "http://proxy.company.com:8080"
  HTTPS_PROXY: "http://proxy.company.com:8080"
  NO_PROXY: "localhost,127.0.0.1,.company.com,.gitlab.com"
  GIT_SSL_NO_VERIFY: "false"

before_script:
  - export http_proxy=$HTTP_PROXY
  - export https_proxy=$HTTPS_PROXY
  - export no_proxy=$NO_PROXY

vulnetix-proxy:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli/v3@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID"
```

### Jenkins

```groovy
pipeline {
    agent any

    environment {
        HTTP_PROXY = 'http://proxy.company.com:8080'
        HTTPS_PROXY = 'http://proxy.company.com:8080'
        NO_PROXY = 'localhost,127.0.0.1,.company.com'
    }

    stages {
        stage('Security Assessment') {
            steps {
                script {
                    // Configure git proxy
                    sh 'git config --global http.proxy $HTTP_PROXY'
                    sh 'git config --global https.proxy $HTTPS_PROXY'

                    // Run Vulnetix
                    sh 'vulnetix --org-id "$VULNETIX_ORG_ID"'
                }
            }
        }
    }
}
```

## Advanced Proxy Scenarios

### PAC (Proxy Auto-Configuration)

```bash
# Download and use PAC file
curl -x http://proxy.company.com:8080 \
  http://wpad.company.com/wpad.dat \
  -o proxy.pac

# Extract proxy for specific URL (requires pac parser)
export HTTP_PROXY=$(pac-resolver proxy.pac https://api.vdb.vulnetix.com/)
export HTTPS_PROXY=$(pac-resolver proxy.pac https://api.vdb.vulnetix.com/)

vulnetix --org-id "your-org-id-here"
```

### Transparent Proxy

```bash
# Configure for transparent proxy environment

# Use automatic proxy detection
vulnetix --org-id "your-org-id-here" \
  --proxy-auto-detect
```

### Proxy Chaining

```bash
# Chain through multiple proxies
export HTTP_PROXY="http://proxy1.company.com:8080"
export HTTPS_PROXY="http://proxy1.company.com:8080"

# Configure proxy1 to forward to proxy2
# (This is typically done at the proxy server level)

vulnetix --org-id "your-org-id-here"
```

### Load Balancer/Proxy Rotation

```bash
#!/bin/bash
# proxy-rotation.sh

PROXIES=(
  "http://proxy1.company.com:8080"
  "http://proxy2.company.com:8080"
  "http://proxy3.company.com:8080"
)

# Select random proxy
PROXY=${PROXIES[$RANDOM % ${#PROXIES[@]}]}

export HTTP_PROXY="$PROXY"
export HTTPS_PROXY="$PROXY"

echo "Using proxy: $PROXY"
vulnetix --org-id "your-org-id-here"
```

## Troubleshooting

### Common Proxy Issues

#### Connection Refused

```bash
# Issue: Connection refused to proxy
# Solution: Verify proxy address and port
telnet proxy.company.com 8080
nc -zv proxy.company.com 8080

# Check proxy service status
curl -x http://proxy.company.com:8080 http://httpbin.org/ip
```

#### Authentication Failures

```bash
# Issue: Proxy authentication failed
# Solution: Verify credentials and encoding

# Test proxy authentication
curl -x http://username:password@proxy.company.com:8080 http://httpbin.org/ip

# URL-encode special characters
python3 -c "import urllib.parse; print(urllib.parse.quote('p@ssw0rd'))"

# Use alternative authentication methods
export HTTP_PROXY="http://$(echo -n 'username:password' | base64)@proxy.company.com:8080"
```

#### Certificate Issues

```bash
# Issue: SSL certificate verification failed
# Solution: Configure certificate trust

# Debug certificate chain
openssl s_client -connect api.vdb.vulnetix.com:443 -proxy proxy.company.com:8080

# Add proxy's certificate to trust store
echo -n | openssl s_client -connect proxy.company.com:8080 | \
  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > proxy-cert.pem
sudo cp proxy-cert.pem /usr/local/share/ca-certificates/proxy.crt
sudo update-ca-certificates
```

#### DNS Resolution Issues

```bash
# Issue: Cannot resolve hostnames
# Solution: Configure DNS properly

# Test DNS resolution
nslookup api.vdb.vulnetix.com 8.8.8.8

# Use alternative DNS

# Bypass DNS for specific hosts
echo '203.0.113.100 api.vdb.vulnetix.com' | sudo tee -a /etc/hosts
```

### Performance Issues

#### Slow Connections

```bash
# Issue: Slow proxy connections
# The 30s per-request timeout is not configurable. Confirm the proxy itself
# is the bottleneck before blaming the CLI:
time curl -x "$HTTPS_PROXY" -o /dev/null -s -w '%{time_total}s\n' \
  https://api.vdb.vulnetix.com/

# Then run with --verbose to see which request stalls
vulnetix --verbose scan
```

#### Bandwidth Limitations

```bash
# Issue: Limited bandwidth through proxy
# Solution: Enable compression and optimize transfers


# Use differential sync for large files

vulnetix --org-id "your-org-id-here" \
  --compression \
  --incremental
```

### Environment Debugging

There is no `--debug`, `--list-proxy-config`, `--test-connectivity`, or
`--generate-connectivity-report`. `--verbose` is the one diagnostic control:
it prints rate limits, retry/backoff timings, cache status, and auth notes to
stderr. It is not a log level.

```bash
# Which credential is active, and from where
vulnetix auth status

# Prove the credential reaches the API through the proxy
vulnetix --verbose auth verify

# Extra diagnostics on a real scan
vulnetix --verbose scan --severity high

# Confirm the proxy itself is reachable, independently of the CLI
curl -x "$HTTPS_PROXY" -sI https://api.vdb.vulnetix.com/ | head -1
```

Because Go reads the proxy environment once per process, exporting `HTTPS_PROXY`
after the CLI has started has no effect — set it before invoking `vulnetix`.

## Security Considerations

### Proxy Security

```bash
# Use encrypted proxy connections when possible
export HTTP_PROXY="https://proxy.company.com:8443"
export HTTPS_PROXY="https://proxy.company.com:8443"

# Verify proxy certificates

# Use mutual TLS authentication
```

### Credential Protection

```bash
# Store proxy credentials securely
# Use environment files
echo 'PROXY_USER=username' > .env.proxy
echo 'PROXY_PASS=password' >> .env.proxy
chmod 600 .env.proxy

# Source credentials
source .env.proxy
export HTTP_PROXY="http://${PROXY_USER}:${PROXY_PASS}@proxy.company.com:8080"

# Use credential helpers
export HTTP_PROXY="http://$(proxy-credential-helper)@proxy.company.com:8080"
```

### Audit and Logging

```bash
# Enable proxy audit logging

# Log proxy usage
vulnetix --org-id "your-org-id-here" \
  --audit-log /var/log/vulnetix-proxy.log

# Monitor proxy performance
vulnetix --org-id "your-org-id-here" \
  --metrics-output proxy-metrics.json
```

For additional corporate environment configurations and advanced networking scenarios, see the [main documentation](../USAGE.md) and other [reference guides](./README.md).
