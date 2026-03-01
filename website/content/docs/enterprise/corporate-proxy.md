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

# Run Vulnetix scan
vulnetix --org-id "your-org-id-here" --task release
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
go install github.com/vulnetix/vulnetix@latest
```

### Docker with Proxy

```bash
# Configure Docker daemon proxy (requires restart)
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf << EOF
[Service]
Environment="HTTP_PROXY=http://proxy.company.com:8080"
Environment="HTTPS_PROXY=http://proxy.company.com:8080"
Environment="NO_PROXY=localhost,127.0.0.1,.company.com"
EOF

sudo systemctl daemon-reload
sudo systemctl restart docker

# Run Vulnetix with proxy
docker run --rm \
  -e HTTP_PROXY="http://proxy.company.com:8080" \
  -e HTTPS_PROXY="http://proxy.company.com:8080" \
  -e NO_PROXY="localhost,127.0.0.1,.company.com" \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"
```

### Binary Download with Proxy

```bash
# Using curl with proxy
curl -x http://proxy.company.com:8080 \
  -L https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-linux-amd64 \
  -o vulnetix

# Using wget with proxy
wget -e use_proxy=yes \
  -e http_proxy=http://proxy.company.com:8080 \
  -e https_proxy=http://proxy.company.com:8080 \
  https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-linux-amd64 \
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
export VULNETIX_SKIP_TLS_VERIFY=true
export CURL_INSECURE=true

# Add self-signed certificate to trust store
openssl s_client -connect app.vulnetix.com:443 -showcerts < /dev/null 2>/dev/null | \
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
# Test connectivity to Vulnetix API
curl -I https://app.vulnetix.com/api/

# Test with proxy
curl -x http://proxy.company.com:8080 -I https://app.vulnetix.com/api/

# Test DNS resolution
nslookup app.vulnetix.com
dig app.vulnetix.com

# Test specific ports
nc -zv app.vulnetix.com 443
telnet app.vulnetix.com 443
```

## Vulnetix-Specific Configuration

### Proxy Configuration File

```yaml
# ~/.vulnetix/config.yaml
proxy:
  http: "http://proxy.company.com:8080"
  https: "http://proxy.company.com:8080"
  no_proxy: "localhost,127.0.0.1,*.internal,.company.com"

network:
  timeout: 60
  retries: 3
  skip_tls_verify: false

api:
  endpoint: "https://app.vulnetix.com/api/"
  timeout: 300
```

### Environment Variable Configuration

```bash
# Vulnetix-specific proxy settings
export VULNETIX_HTTP_PROXY="http://proxy.company.com:8080"
export VULNETIX_HTTPS_PROXY="http://proxy.company.com:8080"
export VULNETIX_NO_PROXY="localhost,127.0.0.1,.company.com"

# API configuration
export VULNETIX_API_URL="https://app.vulnetix.com/api/"
export VULNETIX_TIMEOUT="300"
export VULNETIX_RETRIES="5"

# TLS configuration
export VULNETIX_TLS_CERT="/etc/ssl/certs/vulnetix.crt"
export VULNETIX_TLS_KEY="/etc/ssl/private/vulnetix.key"
export VULNETIX_TLS_CA="/etc/ssl/certs/ca-certificates.crt"
```

### Command Line Options

```bash
# Use proxy with command line options
vulnetix --org-id "your-org-id-here" \
  --proxy "http://proxy.company.com:8080" \
  --no-proxy "localhost,127.0.0.1,.company.com" \
  --task release

# Configure timeouts
vulnetix --org-id "your-org-id-here" \
  --timeout 300 \
  --retries 5 \
  --task release

# Skip TLS verification (not recommended)
vulnetix --org-id "your-org-id-here" \
  --skip-tls-verify \
  --task release
```

## CI/CD Integration with Proxy

### GitHub Actions

```yaml
name: Corporate Proxy Scan

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

      - name: Run Vulnetix scan
        uses: vulnetix/vulnetix@v1
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

vulnetix-proxy-scan:
  stage: security
  image: vulnetix/vulnetix:latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
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
        stage('Security Scan') {
            steps {
                script {
                    // Configure git proxy
                    sh 'git config --global http.proxy $HTTP_PROXY'
                    sh 'git config --global https.proxy $HTTPS_PROXY'

                    // Run Vulnetix scan
                    sh 'vulnetix --org-id "$VULNETIX_ORG_ID" --task release'
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
export HTTP_PROXY=$(pac-resolver proxy.pac https://app.vulnetix.com/api/)
export HTTPS_PROXY=$(pac-resolver proxy.pac https://app.vulnetix.com/api/)

vulnetix --org-id "your-org-id-here" --task release
```

### Transparent Proxy

```bash
# Configure for transparent proxy environment
export VULNETIX_PROXY_AUTO_DETECT=true
export VULNETIX_PROXY_TRANSPARENT=true

# Use automatic proxy detection
vulnetix --org-id "your-org-id-here" \
  --proxy-auto-detect \
  --task release
```

### Proxy Chaining

```bash
# Chain through multiple proxies
export HTTP_PROXY="http://proxy1.company.com:8080"
export HTTPS_PROXY="http://proxy1.company.com:8080"

# Configure proxy1 to forward to proxy2
# (This is typically done at the proxy server level)

vulnetix --org-id "your-org-id-here" --task release
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
vulnetix --org-id "your-org-id-here" --task release
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
openssl s_client -connect app.vulnetix.com:443 -proxy proxy.company.com:8080

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
nslookup app.vulnetix.com 8.8.8.8

# Use alternative DNS
export VULNETIX_DNS_SERVERS="8.8.8.8,8.8.4.4"

# Bypass DNS for specific hosts
echo '203.0.113.100 app.vulnetix.com' | sudo tee -a /etc/hosts
```

### Performance Issues

#### Slow Connections

```bash
# Issue: Slow proxy connections
# Solution: Optimize proxy settings

# Use connection pooling
export VULNETIX_CONNECTION_POOL_SIZE=10
export VULNETIX_KEEP_ALIVE=true

# Increase timeouts
export VULNETIX_TIMEOUT=600
export VULNETIX_CONNECT_TIMEOUT=60

vulnetix --org-id "your-org-id-here" \
  --timeout 600 \
  --retries 3 \
  --task release
```

#### Bandwidth Limitations

```bash
# Issue: Limited bandwidth through proxy
# Solution: Enable compression and optimize transfers

export VULNETIX_COMPRESSION=true
export VULNETIX_TRANSFER_ENCODING="gzip"

# Use differential sync for large files
export VULNETIX_INCREMENTAL_SYNC=true

vulnetix --org-id "your-org-id-here" \
  --compression \
  --incremental \
  --task release
```

### Environment Debugging

```bash
# Debug proxy configuration
vulnetix --debug --list-proxy-config

# Test network connectivity
vulnetix --test-connectivity --verbose

# Trace network requests
export VULNETIX_DEBUG_NETWORK=true
vulnetix --org-id "your-org-id-here" --task release --verbose

# Generate connectivity report
vulnetix --generate-connectivity-report > connectivity-report.json
```

## Security Considerations

### Proxy Security

```bash
# Use encrypted proxy connections when possible
export HTTP_PROXY="https://proxy.company.com:8443"
export HTTPS_PROXY="https://proxy.company.com:8443"

# Verify proxy certificates
export VULNETIX_VERIFY_PROXY_CERT=true

# Use mutual TLS authentication
export VULNETIX_CLIENT_CERT="/etc/ssl/certs/client.crt"
export VULNETIX_CLIENT_KEY="/etc/ssl/private/client.key"
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
export VULNETIX_AUDIT_PROXY=true
export VULNETIX_LOG_PROXY_REQUESTS=true

# Log proxy usage
vulnetix --org-id "your-org-id-here" \
  --audit-log /var/log/vulnetix-proxy.log \
  --task release

# Monitor proxy performance
export VULNETIX_PROXY_METRICS=true
vulnetix --org-id "your-org-id-here" \
  --metrics-output proxy-metrics.json \
  --task release
```

For additional corporate environment configurations and advanced networking scenarios, see the [main documentation](../USAGE.md) and other [reference guides](./README.md).
