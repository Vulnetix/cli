package vdb

import (
	"encoding/json"
	"net/url"
)

// EOLProductResponse is the response from GET /v1/eol/products/{product}.
type EOLProductResponse struct {
	Timestamp int64               `json:"timestamp"`
	Product   EOLProductDetail    `json:"product"`
	Releases  []EOLReleaseDetail  `json:"releases"`
}

// EOLProductDetail contains product metadata.
type EOLProductDetail struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
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
	LatestVersion    *string `json:"latestVersion,omitempty"`
	LatestDate       *string `json:"latestDate,omitempty"`
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
