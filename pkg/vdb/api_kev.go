package vdb

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// VulnetixKevParams holds filter options for GET /v2/vulnetix-kev.
type VulnetixKevParams struct {
	Format            string   // "json" | "csv"
	Reasons           []string // filter by VulnetixKevReason enum values
	FilterMode        string   // "any" | "all" (default: any)
	Limit             int      // JSON pagination
	Offset            int      // JSON pagination
	IncludeReferences bool     // JSON-only; adds the `references` bucket per item
}

func (p VulnetixKevParams) query() string {
	q := url.Values{}
	if p.Format != "" {
		q.Set("format", p.Format)
	}
	for _, r := range p.Reasons {
		q.Add("reason", r)
	}
	if p.FilterMode == "all" {
		q.Set("mode", "all")
	}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", strconv.Itoa(p.Offset))
	}
	if p.IncludeReferences {
		q.Set("include-references", "1")
	}
	return q.Encode()
}

// VulnetixKevList fetches the full Vulnetix KEV catalogue.
// The response bytes are returned verbatim — JSON or CSV per p.Format — so
// callers can write them straight to stdout or a file.
//
// Forces the V2 API (/v2/vulnetix-kev is V2-only).
func (c *Client) VulnetixKevList(p VulnetixKevParams) ([]byte, error) {
	path := "/vulnetix-kev"
	if qs := p.query(); qs != "" {
		path += "?" + qs
	}
	// Temporarily force /v2 regardless of caller's APIVersion setting.
	prev := c.APIVersion
	c.APIVersion = "/v2"
	defer func() { c.APIVersion = prev }()

	return c.DoRequest("GET", path, nil)
}

// VulnetixKevGet fetches a single entry by CVE ID. Implemented client-side as
// a list + filter since the API exposes the catalogue as a collection.
// Returns a NotFoundError if the CVE isn't in the catalogue.
func (c *Client) VulnetixKevGet(cveID string) (map[string]any, error) {
	body, err := c.VulnetixKevList(VulnetixKevParams{
		Format:            "json",
		Limit:             5000,
		IncludeReferences: true,
	})
	if err != nil {
		return nil, err
	}

	var env struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode vulnetix-kev list: %w", err)
	}
	for _, item := range env.Items {
		if id, _ := item["cveId"].(string); id == cveID {
			return item, nil
		}
	}
	return nil, &NotFoundError{Message: fmt.Sprintf("CVE %s is not in the Vulnetix KEV catalogue", cveID)}
}
