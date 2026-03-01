---
title: "VDB Quick Start"
weight: 3
description: "Get started with the Vulnetix Vulnerability Database CLI in minutes with step-by-step setup and first queries."
---

Get started with the Vulnetix Vulnerability Database (VDB) CLI in minutes.

## Prerequisites

- Vulnetix CLI installed
- VDB API credentials (Organization UUID and Secret Key)

## 1. Obtain Credentials

### Option A: Request via Website
Visit https://www.vulnetix.com and complete the demo request form.

### Option B: Email Request
Send an email to sales@vulnetix.com with:
- Subject: "VDB API Access Request"
- Include: Company name, use case, and contact information

You'll receive:
- **Organization UUID**: Format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Secret Key**: 64-character alphanumeric string

## 2. Configure Credentials

### Method 1: Environment Variables (Recommended)

```bash
# Add to your ~/.bashrc, ~/.zshrc, or ~/.profile
export VVD_ORG="your-organization-uuid"
export VVD_SECRET="your-64-character-secret-key"

# Reload your shell configuration
source ~/.bashrc  # or ~/.zshrc
```

### Method 2: Configuration File

```bash
# Create configuration directory
mkdir -p ~/.vulnetix

# Create configuration file
cat > ~/.vulnetix/vdb.json << 'EOF'
{
  "org_id": "your-organization-uuid",
  "secret_key": "your-64-character-secret-key"
}
EOF

# Secure the file
chmod 600 ~/.vulnetix/vdb.json
```

## 3. Verify Setup

```bash
# Test your credentials by listing ecosystems
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

### Check a Famous CVE

```bash
# Get information about Log4Shell
vulnetix vdb cve CVE-2021-44228
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

# 2. Check specific CVEs
vulnetix vdb cve CVE-2024-1234

# 3. Verify if specific version is affected
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

### Bulk CVE Checking

```bash
#!/bin/bash
# check-cves.sh

# Read CVEs from file (one per line)
while IFS= read -r cve; do
  echo "Checking $cve..."
  vulnetix vdb cve "$cve" -o json > "reports/${cve}.json"
  sleep 1  # Rate limiting
done < cve-list.txt
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
# Verify environment variables are set WITHOUT printing secret values
if [ -n "${VVD_ORG:-}" ]; then
  echo "VVD_ORG is set"
else
  echo "VVD_ORG is NOT set"
fi

if [ -n "${VVD_SECRET:-}" ]; then
  echo "VVD_SECRET is set"
else
  echo "VVD_SECRET is NOT set"
fi

# Check that the config file exists (but don't print its contents)
if [ -f "$HOME/.vulnetix/vdb.json" ]; then
  echo "VDB config file found at $HOME/.vulnetix/vdb.json"
else
  echo "VDB config file not found at $HOME/.vulnetix/vdb.json"
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
alias vdb-cve='vulnetix vdb cve'
alias vdb-vulns='vulnetix vdb vulns'

# Now use shorter commands
vdb-cve CVE-2024-1234
vdb-vulns express
```

### Combine with jq

```bash
# Extract CVSS base score
vulnetix vdb cve CVE-2024-1234 -o json | jq '.cvss.v3.baseScore'

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
   echo "vdb.json" >> .gitignore
   ```

2. **Use environment variables in CI/CD**
   ```yaml
   # GitHub Actions example
   - name: Check vulnerabilities
     env:
       VVD_ORG: ${{ secrets.VVD_ORG }}
       VVD_SECRET: ${{ secrets.VVD_SECRET }}
     run: vulnetix vdb vulns ${{ matrix.package }}
   ```

3. **Rotate credentials regularly** for production use

4. **Limit credential access** on shared systems
   ```bash
   chmod 600 ~/.vulnetix/vdb.json
   ```

---

**Ready to go?** Start with `vulnetix vdb ecosystems` and explore!
