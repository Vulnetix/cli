# VDB Subcommand Implementation

This document provides an overview of the VDB subcommand implementation for the Vulnetix CLI.

## Overview

The `vdb` subcommand provides comprehensive access to the Vulnetix Vulnerability Database (VDB) API, enabling users to:

- Query CVE information
- List available package ecosystems
- Retrieve product/package versions
- Find vulnerabilities for specific packages
- Access the OpenAPI specification

## Architecture

### Components

```
vulnetix cli/
├── cmd/
│   └── vdb.go                 # Main VDB command and subcommands
├── internal/
│   └── vdb/
│       ├── client.go          # VDB API client with authentication
│       └── api.go             # API endpoint methods
├── docs/
│   ├── VDB-COMMAND.md         # Full command reference
│   └── VDB-QUICKSTART.md      # Quick start guide
└── examples/
    ├── vdb-config.json        # Example configuration
    ├── vdb-ci-example.sh      # CI/CD integration example
    └── vdb-github-action.yml  # GitHub Actions workflow
```

### Authentication Flow

1. **Credential Loading**:
   - Check command-line flags (`--org-id`, `--secret`)
   - Check environment variables (`VVD_ORG`, `VVD_SECRET`)
   - Check config file (`~/.vulnetix/vdb.json`)

2. **Token Management**:
   - Request JWT token using AWS SigV4 (SHA-512) authentication
   - Cache token with expiration time
   - Automatically refresh when expired (15-minute lifetime)

3. **API Requests**:
   - Use cached JWT token in `Authorization: Bearer <token>` header
   - Handle rate limiting (60 req/min, 1000 req/week)
   - Parse and display responses

## Implementation Details

### Client Package (`internal/vdb/client.go`)

**Key Features**:
- AWS SigV4 SHA-512 request signing
- JWT token caching and automatic refresh
- Credential loading from multiple sources
- HTTP client with 30-second timeout
- Comprehensive error handling

**Main Types**:
```go
type Client struct {
    BaseURL    string
    OrgID      string
    SecretKey  string
    HTTPClient *http.Client
    token      *TokenCache
}

type TokenCache struct {
    Token     string
    ExpiresAt time.Time
}
```

**Key Methods**:
- `NewClient()` - Create new VDB client
- `GetToken()` - Get valid JWT token (from cache or new request)
- `DoRequest()` - Execute authenticated API request
- `signRequest()` - Sign request with AWS SigV4
- `LoadCredentials()` - Load credentials from environment/config

### API Package (`internal/vdb/api.go`)

**Implemented Endpoints**:
- `GetCVE(cveID)` - Get CVE information
- `GetEcosystems()` - List ecosystems
- `GetProductVersions(name, limit, offset)` - List product versions
- `GetProductVersion(name, version)` - Get specific version info
- `GetPackageVulnerabilities(name, limit, offset)` - Get vulnerabilities
- `GetOpenAPISpec()` - Get API specification

**Response Types**:
```go
type CVEInfo struct {
    CVE         string
    Description string
    Published   string
    Modified    string
    CVSS        map[string]interface{}
    References  []interface{}
    Data        map[string]interface{}
}

type ProductVersionsResponse struct {
    PackageName string
    Timestamp   int64
    Total       int
    Limit       int
    Offset      int
    HasMore     bool
    Versions    []string
}
```

### Command Structure (`cmd/vdb.go`)

**Main Command**:
```bash
vulnetix vdb [subcommand] [flags]
```

**Subcommands**:
1. `cve <CVE-ID>` - Get CVE information
2. `ecosystems` - List available ecosystems
3. `product <name> [version]` - Get product/version info
4. `vulns <package>` - Get package vulnerabilities
5. `spec` - Get OpenAPI specification

**Global Flags**:
- `--org-id` - Organization UUID
- `--secret` - Secret key
- `--base-url` - API base URL
- `-o, --output` - Output format (json, pretty)

**Pagination Flags** (for `product` and `vulns`):
- `--limit` - Maximum results (default: 100)
- `--offset` - Results to skip (default: 0)

## Security Considerations

### Credential Management

1. **Never hardcode credentials** in source code
2. **Use environment variables** for CI/CD
3. **Secure config files** with `chmod 600`
4. **Rotate credentials** regularly
5. **Use secrets managers** in production

### Token Security

- JWT tokens expire after 15 minutes
- Tokens cached in memory only (not persisted to disk)
- Automatic token refresh on expiration
- TLS/HTTPS for all API communication

### Rate Limiting

- Per-minute: 60 requests
- Per-week: 1000 requests (default, configurable)
- Rate limit headers in responses
- Graceful error handling

## Usage Examples

### Basic Commands

```bash
# Get CVE information
vulnetix vdb cve CVE-2024-1234

# List ecosystems
vulnetix vdb ecosystems

# Get product versions
vulnetix vdb product express

# Get specific version
vulnetix vdb product express 4.17.1

# Get package vulnerabilities
vulnetix vdb vulns lodash
```

### With Output Formatting

```bash
# JSON output
vulnetix vdb cve CVE-2024-1234 --output json

# Pretty print (default)
vulnetix vdb ecosystems -o pretty

# Save to file
vulnetix vdb spec -o json > api-spec.json
```

### With Pagination

```bash
# Limit results
vulnetix vdb product react --limit 50

# Skip results
vulnetix vdb product react --offset 100

# Combine
vulnetix vdb vulns express --limit 20 --offset 40
```

### CI/CD Integration

```bash
# Set credentials in CI environment
export VVD_ORG="${SECRET_VVD_ORG}"
export VVD_SECRET="${SECRET_VVD_SECRET}"

# Run vulnerability scan
vulnetix vdb vulns my-package -o json > report.json

# Check for critical vulnerabilities
if vulnetix vdb vulns my-package -o json | jq '.vulnerabilities[] | select(.severity == "CRITICAL")' | grep -q .; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

## Testing

### Manual Testing

```bash
# 1. Set test credentials
export VVD_ORG="test-uuid"
export VVD_SECRET="test-secret"

# 2. Test authentication
vulnetix vdb ecosystems

# 3. Test each subcommand
vulnetix vdb cve CVE-2021-44228
vulnetix vdb product express --limit 10
vulnetix vdb vulns lodash
vulnetix vdb spec -o json
```

### Integration Testing

See `examples/vdb-ci-example.sh` for a complete CI/CD test script.

## Error Handling

### Authentication Errors (401)

- Missing or invalid credentials
- Expired JWT token
- Invalid signature

**Solution**: Check credentials, token automatically refreshes

### Rate Limiting (429)

- Exceeded per-minute limit (60 req/min)
- Exceeded weekly quota (1000 req/week)

**Solution**: Wait for reset time, implement backoff, request higher quota

### Not Found (404)

- CVE doesn't exist
- Package not found

**Solution**: Verify identifier spelling

### Server Errors (500)

- Unexpected server error

**Solution**: Retry with exponential backoff

## Future Enhancements

### Potential Features

1. **Response Caching**:
   - Local cache for frequently accessed data
   - Configurable TTL
   - Cache invalidation

2. **Bulk Operations**:
   - Batch CVE queries
   - Bulk package scanning
   - Parallel requests

3. **Advanced Filtering**:
   - Filter by severity
   - Filter by date range
   - CVSS score filtering

4. **Report Generation**:
   - HTML reports
   - PDF exports
   - Custom templates

5. **Notification Integration**:
   - Slack notifications
   - Email alerts
   - Webhook support

6. **Database Export**:
   - Export to SQLite
   - PostgreSQL integration
   - CSV exports

## References

### Documentation

- [VDB API User Guide](./docs/VDB%20API%20User%20Guide%20v1.pdf)
- [Command Reference](./docs/VDB-COMMAND.md)
- [Quick Start Guide](./docs/VDB-QUICKSTART.md)

### API Resources

- **Base URL**: https://api.vdb.vulnetix.com/v1
- **OpenAPI Spec**: https://api.vdb.vulnetix.com/v1/spec
- **Interactive Docs**: https://redocly.github.io/redoc/?url=https://api.vdb.vulnetix.com/v1/spec

### Support

- **Email**: sales@vulnetix.com
- **Website**: https://www.vulnetix.com
- **GitHub**: https://github.com/vulnetix/cli

## Development

### Building

```bash
# Build for development
make dev

# Build for all platforms
make build-all
```

### Adding New Endpoints

1. Add method to `internal/vdb/api.go`
2. Add subcommand to `cmd/vdb.go`
3. Update documentation
4. Add examples

Example:
```go
// internal/vdb/api.go
func (c *Client) GetNewEndpoint() (*Response, error) {
    path := "/new-endpoint"
    respBody, err := c.DoRequest("GET", path, nil)
    if err != nil {
        return nil, err
    }
    var resp Response
    if err := json.Unmarshal(respBody, &resp); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }
    return &resp, nil
}

// cmd/vdb.go
var newCmd = &cobra.Command{
    Use:   "new",
    Short: "Description",
    RunE: func(cmd *cobra.Command, args []string) error {
        client := vdb.NewClient(vdbOrgID, vdbSecretKey)
        result, err := client.GetNewEndpoint()
        if err != nil {
            return err
        }
        return printOutput(result, vdbOutput)
    },
}

func init() {
    vdbCmd.AddCommand(newCmd)
}
```

## License

This implementation follows the Vulnetix CLI license. VDB API data is licensed under MIT License.

## Contributors

- Vulnetix Engineering Team
- Claude Code (AI Assistant)

---

**Status**: ✅ Implementation Complete

**Last Updated**: 2025-12-30
