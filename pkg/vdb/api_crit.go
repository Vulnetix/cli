package vdb

import "encoding/json"

// CritLookupResponse is the response from POST /v1/crit/lookup.
type CritLookupResponse struct {
	Count   int              `json:"count"`
	Matches []CritLookupMatch `json:"matches"`
}

// CritLookupMatch is a single matched CRIT record with enrichment data.
type CritLookupMatch struct {
	Crit           CritRecord          `json:"crit"`
	VulnID         string              `json:"vuln_id"`
	Aliases        []string            `json:"aliases,omitempty"`
	Kev            *CritLookupKev      `json:"kev,omitempty"`
	ExploitSummary *CritLookupExploits `json:"exploit_summary,omitempty"`
	SnortRules     []CritLookupSnortRule `json:"snort_rules,omitempty"`
}

// CritRecord represents a CRIT (Cloud Resource Inventory Template) record.
type CritRecord struct {
	VectorString         string `json:"vectorString"`
	VulnID               string `json:"vuln_id"`
	Provider             string `json:"provider"`
	Service              string `json:"service"`
	ResourceType         string `json:"resource_type"`
	VexStatus            string `json:"vex_status"`
	SharedResponsibility string `json:"shared_responsibility"`
}

// CritLookupKev contains CISA KEV metadata.
type CritLookupKev struct {
	DateAdded                  string `json:"dateAdded"`
	DueDate                    string `json:"dueDate,omitempty"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse,omitempty"`
	RequiredAction             string `json:"requiredAction,omitempty"`
}

// CritLookupExploits contains exploit intelligence summary.
type CritLookupExploits struct {
	Count   int      `json:"count"`
	Sources []string `json:"sources,omitempty"`
}

// CritLookupSnortRule contains an IDS detection rule.
type CritLookupSnortRule struct {
	SnortID           string `json:"snortId"`
	Msg               string `json:"msg"`
	SignatureSeverity string `json:"signatureSeverity,omitempty"`
	RawText           string `json:"rawText,omitempty"`
}

// CritLookup queries the VDB for vulnerabilities matching a CRIT template.
// The CRIT template is defined by provider (e.g. "aws"), service (e.g. "ec2"),
// and resourceType (e.g. "instance").
func (c *Client) CritLookup(provider, service, resourceType string) (*CritLookupResponse, error) {
	body := map[string]string{
		"provider":      provider,
		"service":       service,
		"resource_type": resourceType,
	}
	respBody, err := c.DoRequest("POST", "/crit/lookup", body)
	if err != nil {
		return nil, err
	}
	var result CritLookupResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
