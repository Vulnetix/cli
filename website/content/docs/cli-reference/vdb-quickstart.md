---
title: "VDB Quick Start"
weight: 3
description: "Get started with the Vulnetix Vulnerability Database CLI in minutes with step-by-step setup and first queries."
---

Get started with the Vulnetix Vulnerability Database (VDB) CLI in minutes.

## Prerequisites

- Vulnetix CLI installed
- VDB API credentials (Organization UUID + API key, and/or SigV4 secret)

## 1. Obtain Credentials

### Option A: Request via Website
Visit https://www.vulnetix.com and complete the demo request form.

### Option B: Email Request
Send an email to sales@vulnetix.com with:
- Subject: "VDB API Access Request"
- Include: Company name, use case, and contact information

You'll receive:
- **Organization UUID**: Format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **API Key** (hex digest): Recommended for most use cases (Direct API Key method)
- **Secret Key** (64 characters): For SigV4 authentication

## 2. Configure Credentials

### Method 1: `vulnetix auth login` (Recommended)

```bash
# Interactive — prompts for method, org ID, key, and storage location
vulnetix auth login

# Non-interactive with Direct API Key
vulnetix auth login --org-id UUID --api-key KEY

# Non-interactive with SigV4
vulnetix auth login --org-id UUID --secret KEY
```

### Method 2: Environment Variables

```bash
# Direct API Key (recommended)
export VULNETIX_ORG_ID="your-organization-uuid"
export VULNETIX_API_KEY="your-api-key-hex"

# Or SigV4
export VVD_ORG="your-organization-uuid"
export VVD_SECRET="your-64-character-secret-key"

# Reload your shell configuration
source ~/.bashrc  # or ~/.zshrc
```

### Method 3: Configuration File

```bash
# Create configuration directory
mkdir -p ~/.vulnetix

# Create configuration file (Direct API Key example)
cat > ~/.vulnetix/credentials.json << 'EOF'
{
  "org_id": "your-organization-uuid",
  "api_key": "your-api-key-hex",
  "method": "apikey"
}
EOF

# Secure the file
chmod 600 ~/.vulnetix/credentials.json
```

## 3. Verify Setup

```bash
# Check which credentials are configured
vulnetix auth status

# Verify credentials can authenticate
vulnetix auth verify

# Test with a real query
vulnetix vdb ecosystems
```

Expected output:
```
🌐 Fetching available ecosystems...

✅ Found 50+ ecosystems:

  • npm
  • PyPI
  • Maven
  • Go
  • RubyGems
  ...
```

## 4. Try Your First Queries

### Look Up a Vulnerability

The VDB accepts **78+ identifier formats** — not just CVE. Use whichever identifier you have:

```bash
# By CVE (MITRE / NVD)
vulnetix vdb vuln CVE-2021-44228

# By GitHub Security Advisory
vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9

# By PyPI identifier
vulnetix vdb vuln PYSEC-2024-123

# By Red Hat advisory
vulnetix vdb vuln RHSA-2025:1730

# By Debian advisory
vulnetix vdb vuln DSA-4741-1
```

### Find Package Vulnerabilities

```bash
# Check Express.js vulnerabilities
vulnetix vdb vulns express
```

### List Product Versions

```bash
# List all versions of React
vulnetix vdb product react --limit 20
```

## Common Use Cases

### Security Audit Workflow

```bash
# 1. List all vulnerabilities for your package
vulnetix vdb vulns lodash -o json > audit-results.json

# 2. Look up a specific vulnerability (any identifier format)
vulnetix vdb vuln CVE-2024-1234
vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9

# 3. Check exploit intelligence
vulnetix vdb exploits CVE-2024-1234

# 4. Find available fixes
vulnetix vdb fixes CVE-2024-1234

# 5. Verify if specific version is affected
vulnetix vdb product lodash 4.17.20
```

### CI/CD Integration

```bash
#!/bin/bash
# check-vulnerabilities.sh

PACKAGE_NAME="express"
PACKAGE_VERSION="4.17.1"

# Check for vulnerabilities
VULNS=$(vulnetix vdb vulns $PACKAGE_NAME -o json)
COUNT=$(echo "$VULNS" | jq '.total')

if [ "$COUNT" -gt 0 ]; then
  echo "⚠️  Found $COUNT vulnerabilities in $PACKAGE_NAME"
  exit 1
else
  echo "✅ No vulnerabilities found"
  exit 0
fi
```

### Bulk Vulnerability Checking

```bash
#!/bin/bash
# check-vulns.sh

# Read vulnerability IDs from file (one per line — any format: CVE, GHSA, PYSEC, etc.)
while IFS= read -r vuln_id; do
  echo "Checking $vuln_id..."
  vulnetix vdb vuln "$vuln_id" -o json > "reports/${vuln_id}.json"
  sleep 1  # Rate limiting
done < vuln-list.txt
```

## Next Steps

1. **Read the Full Documentation**: See [VDB Command Reference]({{< relref "vdb" >}})
2. **Explore the API**: `vulnetix vdb spec -o json > api-spec.json`
3. **Automate Checks**: Integrate VDB into your CI/CD pipeline
4. **Monitor Updates**: Subscribe to vulnerability feeds

## Troubleshooting

### "credentials not found" Error

**Problem**: CLI can't find your credentials.

**Solution**:
```bash
# Quickest fix — run interactive login
vulnetix auth login

# Or check all credential sources at once
vulnetix auth status

# Manual check: verify environment variables are set WITHOUT printing secret values
for var in VULNETIX_API_KEY VULNETIX_ORG_ID VVD_ORG VVD_SECRET; do
  if [ -n "${!var:-}" ]; then echo "$var is set"; else echo "$var is NOT set"; fi
done

# Check that the config file exists (but don't print its contents)
if [ -f "$HOME/.vulnetix/credentials.json" ]; then
  echo "Config file found at $HOME/.vulnetix/credentials.json"
else
  echo "Config file not found at $HOME/.vulnetix/credentials.json"
fi

# Security tip: avoid running commands that print secrets (UUIDs, API keys,
# or full config files) directly to your terminal or CI logs.
```

### "Invalid signature" Error

**Problem**: Credentials are incorrect or malformed.

**Solution**:
- Verify your Organization UUID is a valid UUID format
- Ensure Secret Key is exactly 64 characters
- Check for extra spaces or newlines in credentials
- Request new credentials if needed

### "Rate limit exceeded" Error

**Problem**: Too many requests in a short time.

**Solution**:
- Wait for the reset time shown in the error message
- Default: 60 requests per minute, 1000 per week
- Add delays between requests in scripts
- Contact sales@vulnetix.com for higher quotas

### "Token has expired" Error

**Problem**: JWT token expired (15-minute lifetime).

**Solution**:
- The CLI automatically refreshes tokens
- This error usually self-resolves on retry
- If persistent, check system clock synchronization

## Advanced Tips

### Use Aliases

```bash
# Add to ~/.bashrc or ~/.zshrc
alias vdb='vulnetix vdb'
alias vdb-vuln='vulnetix vdb vuln'
alias vdb-vulns='vulnetix vdb vulns'

# Now use shorter commands
vdb-vuln CVE-2024-1234
vdb-vulns express
```

### Combine with jq

```bash
# Extract data from any vulnerability identifier
vulnetix vdb vuln CVE-2021-44228 -o json | jq '.[0].containers.cna.title'
vulnetix vdb vuln GHSA-jfh8-3a1q-hjz9 -o json | jq '.[0].containers.cna.title'

# Get high severity vulns only
vulnetix vdb vulns lodash -o json | \
  jq '.vulnerabilities[] | select(.severity == "HIGH")'

# Count vulnerabilities by severity
vulnetix vdb vulns webpack -o json | \
  jq -r '.vulnerabilities[].severity' | \
  sort | uniq -c
```

### Cache Results

```bash
# Cache ecosystems list
vulnetix vdb ecosystems -o json > ~/.vulnetix/cache/ecosystems.json

# Use cached data
cat ~/.vulnetix/cache/ecosystems.json | jq
```

### Create Reports

```bash
#!/bin/bash
# generate-report.sh

PACKAGES=("express" "lodash" "react" "axios")
REPORT_DIR="vulnerability-report-$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

for pkg in "${PACKAGES[@]}"; do
  echo "Scanning $pkg..."
  vulnetix vdb vulns "$pkg" -o json > "$REPORT_DIR/${pkg}-vulns.json"
done

echo "Report generated in $REPORT_DIR/"
```

## Support Resources

- **Documentation**: See [VDB Command Reference]({{< relref "vdb" >}})
- **API Spec**: https://api.vdb.vulnetix.com/v1/spec
- **Email Support**: sales@vulnetix.com
- **Website**: https://www.vulnetix.com

## Security Best Practices

1. **Never commit credentials** to Git
   ```bash
   # Add to .gitignore
   echo ".vulnetix/" >> .gitignore
   echo "credentials.json" >> .gitignore
   ```

2. **Use environment variables in CI/CD**
   ```yaml
   # GitHub Actions example (Direct API Key — recommended)
   - name: Check vulnerabilities
     env:
       VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
       VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
     run: vulnetix vdb vulns ${{ matrix.package }}

   # Or SigV4
   - name: Check vulnerabilities
     env:
       VVD_ORG: ${{ secrets.VVD_ORG }}
       VVD_SECRET: ${{ secrets.VVD_SECRET }}
     run: vulnetix vdb vulns ${{ matrix.package }}
   ```

3. **Rotate credentials regularly** for production use

4. **Limit credential access** on shared systems
   ```bash
   chmod 600 ~/.vulnetix/credentials.json
   ```

---

**Ready to go?** Start with `vulnetix vdb ecosystems` and explore!
