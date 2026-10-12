package vdb

// The input model every input-taking v2 route accepts (vdb-api internal/inputs,
// rules in vdb-api .repo/inputs.md). A caller names the software or the
// vulnerability in whatever form it holds; kinds given together narrow the
// answer.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Inputs names a vulnerability or software in any of the forms the API accepts.
// Every field is optional.
type Inputs struct {
	VulnIDs   []string `json:"vulnIds,omitempty"`
	Package   string   `json:"package,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Version   string   `json:"version,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Product   string   `json:"product,omitempty"`
	CPE       string   `json:"cpe,omitempty"`
	PURL      string   `json:"purl,omitempty"`
	SWID      string   `json:"swid,omitempty"`
	TEI       string   `json:"tei,omitempty"`
	CEL       string   `json:"cel,omitempty"`
}

// Empty reports whether no input kind is set.
func (in Inputs) Empty() bool {
	return len(in.VulnIDs) == 0 && in.Package == "" && in.Ecosystem == "" && in.Version == "" &&
		in.Vendor == "" && in.Product == "" && in.CPE == "" && in.PURL == "" &&
		in.SWID == "" && in.TEI == "" && in.CEL == ""
}

// Kinds lists the input kinds set, in a fixed order, for display.
func (in Inputs) Kinds() []string {
	var out []string
	for _, k := range []struct {
		name string
		set  bool
	}{
		{"vulnId", len(in.VulnIDs) > 0}, {"package", in.Package != ""}, {"ecosystem", in.Ecosystem != ""},
		{"version", in.Version != ""}, {"vendor", in.Vendor != ""}, {"product", in.Product != ""},
		{"cpe", in.CPE != ""}, {"purl", in.PURL != ""}, {"swid", in.SWID != ""},
		{"tei", in.TEI != ""}, {"cel", in.CEL != ""},
	} {
		if k.set {
			out = append(out, k.name)
		}
	}
	return out
}

// Encode adds the inputs to a query string under the API's parameter names.
func (in Inputs) Encode(q url.Values) {
	for _, id := range in.VulnIDs {
		q.Add("vulnId", id)
	}
	for k, v := range map[string]string{
		"package": in.Package, "ecosystem": in.Ecosystem, "version": in.Version,
		"vendor": in.Vendor, "product": in.Product, "cpe": in.CPE, "purl": in.PURL,
		"swid": in.SWID, "tei": in.TEI, "cel": in.CEL,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
}

// NeedsBody reports whether the inputs belong in a JSON body rather than a
// query string: a SWID tag or a CEL expression, or anything long.
func (in Inputs) NeedsBody() bool {
	if in.SWID != "" || in.CEL != "" {
		return true
	}
	q := url.Values{}
	in.Encode(q)
	return len(q.Encode()) > 1500
}

// Label is a short description of the inputs, for output and analytics.
func (in Inputs) Label() string {
	switch {
	case in.PURL != "":
		return in.PURL
	case in.CPE != "":
		return in.CPE
	case in.TEI != "":
		return in.TEI
	case in.Package != "":
		s := in.Package
		if in.Ecosystem != "" {
			s = in.Ecosystem + ":" + s
		}
		if in.Version != "" {
			s += "@" + in.Version
		}
		return s
	case in.Product != "":
		s := strings.TrimSpace(in.Vendor + " " + in.Product)
		if in.Version != "" {
			s += " " + in.Version
		}
		return s
	case len(in.VulnIDs) > 0:
		return strings.Join(in.VulnIDs, ",")
	case in.CEL != "":
		return "cel: " + in.CEL
	case in.SWID != "":
		return "swid tag"
	}
	return ""
}

// ResolvedInputs is what the API read the inputs as.
type ResolvedInputs struct {
	Kinds        []string `json:"kinds"`
	VulnIDs      []string `json:"vulnIds"`
	Truncated    bool     `json:"truncated,omitempty"`
	Versionless  bool     `json:"versionless,omitempty"`
	AnyEcosystem bool     `json:"anyEcosystem,omitempty"`
	Packages     []struct {
		Ecosystem string `json:"ecosystem,omitempty"`
		Name      string `json:"name"`
		Version   string `json:"version,omitempty"`
	} `json:"packages,omitempty"`
	Products []struct {
		Vendor  string `json:"vendor,omitempty"`
		Product string `json:"product"`
		Version string `json:"version,omitempty"`
	} `json:"products,omitempty"`
}

// ── bulk defence counts ────────────────────────────────────────────────

// DefenceCountsMaxItems is the most items one request may carry.
const DefenceCountsMaxItems = 100

// DefenceCountsItem is one input set to count defences for. Key is echoed back
// on its result.
type DefenceCountsItem struct {
	Key string `json:"key,omitempty"`
	Inputs
}

// DefenceBrief is one defence as the counts endpoint lists it.
type DefenceBrief struct {
	UUID              string `json:"uuid"`
	Kind              string `json:"kind"`
	Title             string `json:"title"`
	DeployMode        string `json:"deployMode,omitempty"`
	Confidence        string `json:"confidence,omitempty"`
	FalsePositiveRisk string `json:"falsePositiveRisk,omitempty"`
	MatchedCve        string `json:"matchedCve,omitempty"`
	ConsoleURL        string `json:"consoleUrl"`
}

// DefenceLaneCounts is one lane's answer for one item. Defences is nil when the
// caller's plan does not include them (the counts are still there).
type DefenceLaneCounts struct {
	Total    int            `json:"total"`
	ByKind   map[string]int `json:"byKind"`
	HasMore  bool           `json:"hasMore"`
	Defences []DefenceBrief `json:"defences"`
}

// DefenceItemError is an item's inputs the caller must fix; the other items are
// still answered.
type DefenceItemError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func (e *DefenceItemError) Error() string { return e.Field + ": " + e.Message }

// DefenceCountsResult is one item's answer.
type DefenceCountsResult struct {
	Key             string             `json:"key,omitempty"`
	Resolved        *ResolvedInputs    `json:"resolved,omitempty"`
	VirtualPatches  *DefenceLaneCounts `json:"virtualPatches,omitempty"`
	Countermeasures *DefenceLaneCounts `json:"countermeasures,omitempty"`
	Error           *DefenceItemError  `json:"error,omitempty"`
}

// DefenceCountsResponse is the bulk counts answer.
type DefenceCountsResponse struct {
	SchemaVersion string                `json:"schemaVersion"`
	Tier          string                `json:"tier"`
	Items         []DefenceCountsResult `json:"items"`
	Entitlements  json.RawMessage       `json:"_entitlements,omitempty"`
}

// Gated reports whether the plan withheld the defence lists.
func (r *DefenceCountsResponse) Gated() bool { return len(r.Entitlements) > 0 }

// V2DefenceCounts counts virtual patches and countermeasures for many inputs:
// counts for every plan, the defences with their console links for Pro. More
// than DefenceCountsMaxItems items are sent in several requests and the
// results joined in order.
func (c *Client) V2DefenceCounts(items []DefenceCountsItem) (*DefenceCountsResponse, error) {
	out := &DefenceCountsResponse{}
	for start := 0; start < len(items); start += DefenceCountsMaxItems {
		end := min(start+DefenceCountsMaxItems, len(items))
		body, err := c.DoRequest("POST", "/defences/counts", map[string]any{"items": items[start:end]})
		if err != nil {
			return nil, err
		}
		if pl, locked := decodePlanLocked(body); locked {
			return nil, pl
		}
		var page DefenceCountsResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("failed to parse defence counts: %w", err)
		}
		out.SchemaVersion, out.Tier = page.SchemaVersion, page.Tier
		if len(page.Entitlements) > 0 {
			out.Entitlements = page.Entitlements
		}
		out.Items = append(out.Items, page.Items...)
	}
	return out, nil
}

// V2ResolveInputs asks the API what the inputs resolve to: the vulnerability
// ids (aliases included) and how each input was read.
func (c *Client) V2ResolveInputs(in Inputs) (*ResolvedInputs, error) {
	var (
		body []byte
		err  error
	)
	if in.NeedsBody() {
		body, err = c.DoRequest("POST", "/inputs/resolve", in)
	} else {
		q := url.Values{}
		in.Encode(q)
		body, err = c.DoRequest("GET", "/inputs/resolve?"+q.Encode(), nil)
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Resolved ResolvedInputs `json:"resolved"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to parse resolved inputs: %w", err)
	}
	return &out.Resolved, nil
}
