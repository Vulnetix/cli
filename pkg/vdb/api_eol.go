package vdb

import (
	"encoding/json"
	"errors"
	"net/url"
)

// EOLProductResponse is the response from GET /v1/eol/products/{product}.
type EOLProductResponse struct {
	Timestamp int64            `json:"timestamp"`
	Product   EOLProductDetail `json:"product"`
}

// EOLProductDetail contains product metadata and every release the EOL
// database tracks for it.
//
// Releases is nested here, not at the top level of the response: the server
// returns {"product": {..., "releases": [...]}}, and a top-level Releases field
// decoded to nil on every product without any error surfacing.
type EOLProductDetail struct {
	Name           string             `json:"name"`
	Label          string             `json:"label"`
	Category       string             `json:"category"`
	Tags           []string           `json:"tags"`
	Aliases        []string           `json:"aliases,omitempty"`
	VersionCommand *string            `json:"versionCommand,omitempty"`
	Releases       []EOLReleaseDetail `json:"releases"`
}

// EOLLatest is the newest release the feed knows of for a lifecycle entry.
type EOLLatest struct {
	Name *string `json:"name,omitempty"`
	Date *string `json:"date,omitempty"`
	Link *string `json:"link,omitempty"`
}

// EOLReleaseDetail contains lifecycle data for a single release.
type EOLReleaseDetail struct {
	Name             string  `json:"name"`
	Codename         *string `json:"codename,omitempty"`
	Label            string  `json:"label"`
	ReleaseDate      *string `json:"releaseDate,omitempty"`
	IsLts            bool    `json:"isLts"`
	LtsFrom          *string `json:"ltsFrom,omitempty"`
	IsEoas           bool    `json:"isEoas"`
	EoasFrom         *string `json:"eoasFrom,omitempty"`
	IsEol            bool    `json:"isEol"`
	EolFrom          *string `json:"eolFrom,omitempty"`
	IsEoes           *bool   `json:"isEoes,omitempty"`
	EoesFrom         *string `json:"eoesFrom,omitempty"`
	IsDiscontinued   *bool   `json:"isDiscontinued,omitempty"`
	DiscontinuedFrom *string `json:"discontinuedFrom,omitempty"`
	IsMaintained     bool    `json:"isMaintained"`
	// Latest is an object on the wire — {"name","date","link"} — not the flat
	// latestVersion/latestDate pair this type used to declare, which never
	// decoded to anything.
	Latest *EOLLatest `json:"latest,omitempty"`
}

// LatestVersion returns the newest known version, or nil when the feed has none.
func (r EOLReleaseDetail) LatestVersion() *string {
	if r.Latest == nil {
		return nil
	}
	return r.Latest.Name
}

// LatestDate returns the newest known release date, or nil when the feed has none.
func (r EOLReleaseDetail) LatestDate() *string {
	if r.Latest == nil {
		return nil
	}
	return r.Latest.Date
}

// EOLReleaseResponse is the response from GET /v1/eol/products/{product}/releases/{release}.
type EOLReleaseResponse struct {
	Timestamp   int64            `json:"timestamp"`
	ProductName string           `json:"productName"`
	Release     EOLReleaseDetail `json:"release"`
}

// EOLProduct retrieves product metadata and all releases for an EOL product.
func (c *Client) EOLProduct(product string) (*EOLProductResponse, error) {
	path := "/eol/products/" + url.PathEscape(product)
	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var result EOLProductResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EOLPackageVersion retrieves EOL lifecycle data for a specific package version.
// Returns (nil, nil) when the package/version is not in the VDB EOL database (404).
// Endpoint: GET /v1/eol/packages/{ecosystem}/{package}/versions/{version}
func (c *Client) EOLPackageVersion(ecosystem, packageName, version string) (*EOLReleaseResponse, error) {
	path := "/eol/packages/" + url.PathEscape(ecosystem) +
		"/" + url.PathEscape(packageName) +
		"/versions/" + url.PathEscape(version)
	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		var nfe *NotFoundError
		if errors.As(err, &nfe) {
			return nil, nil // not in EOL database — not a breach
		}
		return nil, nil // network error — silently skip
	}
	var result EOLReleaseResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EOLRelease retrieves lifecycle data for a specific product release.
func (c *Client) EOLRelease(product, release string) (*EOLReleaseResponse, error) {
	path := "/eol/products/" + url.PathEscape(product) + "/releases/" + url.PathEscape(release)
	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var result EOLReleaseResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
