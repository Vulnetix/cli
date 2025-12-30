#!/bin/bash
#
# Example: VDB Vulnerability Scanning in CI/CD
#
# This script demonstrates how to integrate VDB API into your CI/CD pipeline
# to check for vulnerabilities in your dependencies.
#
# Usage:
#   ./vdb-ci-example.sh <package-name> [severity-threshold]
#
# Environment Variables Required:
#   VVD_ORG     - Your organization UUID
#   VVD_SECRET  - Your secret key
#
# Exit Codes:
#   0 - No vulnerabilities found or below threshold
#   1 - Vulnerabilities found above threshold
#   2 - Error occurred

set -e

PACKAGE_NAME="${1:-}"
SEVERITY_THRESHOLD="${2:-HIGH}"  # CRITICAL, HIGH, MEDIUM, LOW

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Validate inputs
if [ -z "$PACKAGE_NAME" ]; then
    echo "Usage: $0 <package-name> [severity-threshold]"
    echo "Example: $0 express HIGH"
    exit 2
fi

# Check credentials
if [ -z "$VVD_ORG" ] || [ -z "$VVD_SECRET" ]; then
    echo -e "${RED}Error: VVD_ORG and VVD_SECRET environment variables must be set${NC}"
    exit 2
fi

echo "🔍 Scanning $PACKAGE_NAME for vulnerabilities..."
echo "📊 Severity threshold: $SEVERITY_THRESHOLD"
echo ""

# Fetch vulnerabilities
VULNS_JSON=$(vulnetix vdb vulns "$PACKAGE_NAME" -o json 2>&1)

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to fetch vulnerabilities${NC}"
    echo "$VULNS_JSON"
    exit 2
fi

# Parse results
TOTAL=$(echo "$VULNS_JSON" | jq -r '.total')
CRITICAL=$(echo "$VULNS_JSON" | jq '[.vulnerabilities[] | select(.severity == "CRITICAL")] | length')
HIGH=$(echo "$VULNS_JSON" | jq '[.vulnerabilities[] | select(.severity == "HIGH")] | length')
MEDIUM=$(echo "$VULNS_JSON" | jq '[.vulnerabilities[] | select(.severity == "MEDIUM")] | length')
LOW=$(echo "$VULNS_JSON" | jq '[.vulnerabilities[] | select(.severity == "LOW")] | length')

# Display summary
echo "📋 Vulnerability Summary:"
echo "  Total: $TOTAL"
echo -e "  ${RED}Critical: $CRITICAL${NC}"
echo -e "  ${YELLOW}High: $HIGH${NC}"
echo "  Medium: $MEDIUM"
echo "  Low: $LOW"
echo ""

# Determine if build should fail
FAIL_BUILD=false

case "$SEVERITY_THRESHOLD" in
    CRITICAL)
        if [ "$CRITICAL" -gt 0 ]; then
            FAIL_BUILD=true
        fi
        ;;
    HIGH)
        if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            FAIL_BUILD=true
        fi
        ;;
    MEDIUM)
        if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ]; then
            FAIL_BUILD=true
        fi
        ;;
    LOW)
        if [ "$TOTAL" -gt 0 ]; then
            FAIL_BUILD=true
        fi
        ;;
esac

if [ "$FAIL_BUILD" = true ]; then
    echo -e "${RED}❌ Build failed: Vulnerabilities found above threshold${NC}"
    echo ""
    echo "Critical/High vulnerabilities:"
    echo "$VULNS_JSON" | jq -r '.vulnerabilities[] | select(.severity == "CRITICAL" or .severity == "HIGH") | "  - \(.id // .cve): \(.severity)"'
    exit 1
else
    echo -e "${GREEN}✅ Build passed: No vulnerabilities above threshold${NC}"
    exit 0
fi
