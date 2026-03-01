package vdb

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// CVEInfo represents vulnerability information for a CVE
type CVEInfo struct {
	Data interface{} // Store full response for display (array or object)
}

// EcosystemsResponse represents the ecosystems list response
type EcosystemsResponse struct {
	Ecosystems []string `json:"ecosystems"`
}

// ProductVersionsResponse represents product versions with pagination
type ProductVersionsResponse struct {
	PackageName string   `json:"packageName"`
	Timestamp   int64    `json:"timestamp"`
	Total       int      `json:"total"`
	Limit       int      `json:"limit"`
	Offset      int      `json:"offset"`
	HasMore     bool     `json:"hasMore"`
	Versions    []string `json:"versions"`
}

// VulnerabilitiesResponse represents vulnerabilities for a package
type VulnerabilitiesResponse struct {
	PackageName      string                   `json:"packageName"`
	Timestamp        int64                    `json:"timestamp"`
	Total            int                      `json:"total"`
	Limit            int                      `json:"limit"`
	Offset           int                      `json:"offset"`
	HasMore          bool                     `json:"hasMore"`
	Vulnerabilities  []map[string]interface{} `json:"vulnerabilities"`
}

// GetCVE retrieves full vulnerability data for a specific CVE
func (c *Client) GetCVE(cveID string) (*CVEInfo, error) {
	path := fmt.Sprintf("/vuln/%s", cveID)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var data interface{}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &CVEInfo{Data: data}, nil
}

// GetEcosystems retrieves the list of available ecosystems
func (c *Client) GetEcosystems() ([]string, error) {
	path := "/ecosystems"

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp EcosystemsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Ecosystems, nil
}

// buildPaginationQuery constructs a query string for pagination parameters.
// It returns an empty string if neither limit nor offset is greater than zero.
func buildPaginationQuery(limit, offset int) string {
	if limit <= 0 && offset <= 0 {
		return ""
	}

	params := url.Values{}
	if limit > 0 {
		params.Add("limit", fmt.Sprintf("%d", limit))
	}
	if offset > 0 {
		params.Add("offset", fmt.Sprintf("%d", offset))
	}

	return "?" + params.Encode()
}

// GetProductVersions retrieves all versions for a product with pagination
func (c *Client) GetProductVersions(productName string, limit, offset int) (*ProductVersionsResponse, error) {
	path := fmt.Sprintf("/product/%s", url.PathEscape(productName))

	// Add pagination parameters
	path += buildPaginationQuery(limit, offset)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp ProductVersionsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetProductVersion retrieves information for a specific product version
func (c *Client) GetProductVersion(productName, version string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/product/%s/%s", url.PathEscape(productName), url.PathEscape(version))

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetPackageVulnerabilities retrieves vulnerabilities for a package
func (c *Client) GetPackageVulnerabilities(packageName string, limit, offset int) (*VulnerabilitiesResponse, error) {
	path := fmt.Sprintf("/%s/vulns", url.PathEscape(packageName))

	// Add pagination parameters
	path += buildPaginationQuery(limit, offset)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp VulnerabilitiesResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetOpenAPISpec retrieves the OpenAPI specification
func (c *Client) GetOpenAPISpec() (map[string]interface{}, error) {
	path := "/spec"

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(respBody, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return spec, nil
}
