package vdb

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VulnetixKevParams holds filter options for GET /v2/vulnetix-kev.
type VulnetixKevParams struct {
	Format            string   // "json" | "csv"
	Reasons           []string // filter by VulnetixKevReason enum values
	FilterMode        string   // "any" | "all" (default: any)
	Limit             int      // JSON pagination
	Offset            int      // JSON pagination
	IncludeReferences bool     // JSON-only; adds the `references` bucket per item
	// Include appends authority catalogues as their own rows: "cisa", "enisa".
	// Every row carries `source`. VulnCheck is not an option; it is a vendor
	// superset of CISA, not an authority.
	Include []string
}

func (p VulnetixKevParams) query() string {
	q := url.Values{}
	if p.Format != "" {
		q.Set("format", p.Format)
	}
	if len(p.Include) > 0 {
		q.Set("include", strings.Join(p.Include, ","))
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

// kevGetPageSize is how many rows one page of the catalogue holds.
const kevGetPageSize = 2000

// VulnetixKevGet fetches the KEV entry for a CVE.
//
// It searches every catalogue the API folds together, not only Vulnetix's own.
// Vulnetix's catalogue is deliberately the CVEs that CISA and ENISA do not list,
// so searching it alone answered "not in the Vulnetix KEV catalogue" for Log4Shell,
// Heartbleed and Spring4Shell, which reads as "not a known exploited
// vulnerability". The result names each catalogue that lists the CVE.
//
// The API exposes the catalogues as a paged collection, so this lists and
// filters client-side. It returns a NotFoundError if no catalogue lists the CVE.
func (c *Client) VulnetixKevGet(cveID string) (map[string]any, error) {
	return kevGetFrom(func(offset int) ([]byte, error) {
		return c.VulnetixKevList(VulnetixKevParams{
			Format:            "json",
			Limit:             kevGetPageSize,
			Offset:            offset,
			IncludeReferences: true,
			Include:           []string{"cisa", "enisa"},
		})
	}, cveID)
}

// kevGetFrom is VulnetixKevGet over any pager, so it can be tested without a
// network.
func kevGetFrom(page func(offset int) ([]byte, error), cveID string) (map[string]any, error) {
	var found map[string]any
	var catalogues []string
	seen := map[string]bool{}
	for offset := 0; ; offset += kevGetPageSize {
		body, err := page(offset)
		if err != nil {
			return nil, err
		}
		var env struct {
			Total int              `json:"total"`
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return nil, fmt.Errorf("decode vulnetix-kev list: %w", err)
		}
		for _, item := range env.Items {
			if id, _ := item["cveId"].(string); strings.EqualFold(id, cveID) {
				if found == nil {
					found = item
				}
				src, _ := item["source"].(string)
				if src == "" {
					src = "vulnetix"
				}
				if !seen[src] {
					seen[src] = true
					catalogues = append(catalogues, src)
				}
			}
		}
		if len(env.Items) < kevGetPageSize || offset+len(env.Items) >= env.Total {
			break
		}
	}
	if found == nil {
		return nil, &NotFoundError{Message: fmt.Sprintf("CVE %s is in none of the KEV catalogues checked (Vulnetix, CISA, ENISA)", cveID)}
	}
	out := make(map[string]any, len(found)+1)
	for k, v := range found {
		out[k] = v
	}
	out["catalogues"] = catalogues
	return out, nil
}
