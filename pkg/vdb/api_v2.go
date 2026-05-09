package vdb

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

// V2QueryParams holds common context-filter query parameters for V2 endpoints.
type V2QueryParams struct {
	Ecosystem   string
	PackageName string
	Vendor      string
	Product     string
	Distro      string
	Purl        string
	Limit       int
	Offset      int
}

// V2RemediationParams extends V2QueryParams with remediation-plan-specific parameters.
type V2RemediationParams struct {
	V2QueryParams
	CurrentVersion           string
	PackageManager           string
	ContainerImage           string
	OS                       string
	Registry                 string
	IncludeGuidance          bool
	IncludeVerificationSteps bool
}

// v2QueryString builds a URL query string from V2QueryParams.
func v2QueryString(p V2QueryParams) string {
	q := url.Values{}
	if p.Ecosystem != "" {
		q.Set("ecosystem", p.Ecosystem)
	}
	if p.PackageName != "" {
		q.Set("packageName", p.PackageName)
	}
	if p.Vendor != "" {
		q.Set("vendor", p.Vendor)
	}
	if p.Product != "" {
		q.Set("product", p.Product)
	}
	if p.Distro != "" {
		q.Set("distro", p.Distro)
	}
	if p.Purl != "" {
		q.Set("purl", p.Purl)
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	if encoded := q.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

func doV2Get(c *Client, path string) (map[string]interface{}, error) {
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

// V2RegistryFixes retrieves registry-sourced fixes for a vulnerability.
func (c *Client) V2RegistryFixes(id string, p V2QueryParams) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/fixes/registry%s", url.PathEscape(id), v2QueryString(p))
	return doV2Get(c, path)
}

// V2DistributionPatches retrieves distribution patch data for a vulnerability.
func (c *Client) V2DistributionPatches(id string, p V2QueryParams) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/fixes/distributions%s", url.PathEscape(id), v2QueryString(p))
	return doV2Get(c, path)
}

// V2SourceFixes retrieves upstream source fixes for a vulnerability.
func (c *Client) V2SourceFixes(id string, p ...V2QueryParams) (map[string]interface{}, error) {
	qs := ""
	if len(p) > 0 {
		qs = v2QueryString(p[0])
	}
	path := fmt.Sprintf("/vuln/%s/fixes/source%s", url.PathEscape(id), qs)
	return doV2Get(c, path)
}

// V2Workarounds retrieves workaround information for a vulnerability.
func (c *Client) V2Workarounds(id string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/workarounds", url.PathEscape(id))
	return doV2Get(c, path)
}

// V2Advisories retrieves advisory data for a vulnerability.
func (c *Client) V2Advisories(id string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/advisories", url.PathEscape(id))
	return doV2Get(c, path)
}

// V2CweGuidance retrieves CWE-based guidance for a vulnerability.
func (c *Client) V2CweGuidance(id string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/cwe-guidance", url.PathEscape(id))
	return doV2Get(c, path)
}

// V2Kev retrieves CISA KEV (Known Exploited Vulnerabilities) data.
func (c *Client) V2Kev(id string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/kev", url.PathEscape(id))
	return doV2Get(c, path)
}

// V2TimelineParams holds filter parameters for the v2 timeline endpoint.
type V2TimelineParams struct {
	Include     string // comma-separated event types to include
	Exclude     string // comma-separated event types to exclude
	Dates       string // comma-separated CVE date fields: published,modified,reserved
	ScoresLimit int    // max score-change events (default 30, max 365)
}

// V2Timeline retrieves the vulnerability timeline with optional filters.
func (c *Client) V2Timeline(id string, p V2TimelineParams) (map[string]interface{}, error) {
	q := url.Values{}
	if p.Include != "" {
		q.Set("include", p.Include)
	}
	if p.Exclude != "" {
		q.Set("exclude", p.Exclude)
	}
	if p.Dates != "" {
		q.Set("dates", p.Dates)
	}
	if p.ScoresLimit > 0 {
		q.Set("scores_limit", fmt.Sprintf("%d", p.ScoresLimit))
	}
	path := fmt.Sprintf("/vuln/%s/timeline", url.PathEscape(id))
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

// V2Affected retrieves affected product/package data for a vulnerability.
func (c *Client) V2Affected(id string, p V2QueryParams) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/affected%s", url.PathEscape(id), v2QueryString(p))
	return doV2Get(c, path)
}

// V2Scorecard retrieves the vulnerability scorecard.
func (c *Client) V2Scorecard(id string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/scorecard", url.PathEscape(id))
	return doV2Get(c, path)
}

// V2ScorecardSearch searches scorecards by repository name.
func (c *Client) V2ScorecardSearch(query string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/scorecard/search?q=%s", url.QueryEscape(query))
	return doV2Get(c, path)
}

// V2RemediationPlan retrieves a context-aware remediation plan for a vulnerability.
func (c *Client) V2RemediationPlan(id string, p V2RemediationParams) (map[string]interface{}, error) {
	q := url.Values{}
	if p.Ecosystem != "" {
		q.Set("ecosystem", p.Ecosystem)
	}
	if p.PackageName != "" {
		q.Set("packageName", p.PackageName)
	}
	if p.Vendor != "" {
		q.Set("vendor", p.Vendor)
	}
	if p.Product != "" {
		q.Set("product", p.Product)
	}
	if p.Distro != "" {
		q.Set("distro", p.Distro)
	}
	if p.Purl != "" {
		q.Set("purl", p.Purl)
	}
	if p.CurrentVersion != "" {
		q.Set("currentVersion", p.CurrentVersion)
	}
	if p.PackageManager != "" {
		q.Set("packageManager", p.PackageManager)
	}
	if p.ContainerImage != "" {
		q.Set("containerImage", p.ContainerImage)
	}
	if p.OS != "" {
		q.Set("os", p.OS)
	}
	if p.Registry != "" {
		q.Set("registry", p.Registry)
	}
	if p.IncludeGuidance {
		q.Set("includeGuidance", "true")
	}
	if p.IncludeVerificationSteps {
		q.Set("includeVerificationSteps", "true")
	}

	path := fmt.Sprintf("/vuln/%s/remediation-plan", url.PathEscape(id))
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}

	return doV2Get(c, path)
}

// V2ScanManifest uploads a manifest file for scanning.
// An optional metadata parameter (JSON bytes) is sent as the "metadata" form field.
func (c *Client) V2ScanManifest(filePath, manifestType, ecosystem string, metadata ...[]byte) (map[string]interface{}, error) {
	fields := map[string]string{
		"type": manifestType,
	}
	if ecosystem != "" {
		fields["ecosystem"] = ecosystem
	}
	if len(metadata) > 0 && len(metadata[0]) > 0 {
		fields["metadata"] = string(metadata[0])
	}

	respBody, err := c.DoRequestMultipart("/scan/manifest", filePath, "file", fields)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// V2ScanSPDX uploads an SPDX document for scanning.
// An optional metadata parameter (JSON bytes) is sent as a query parameter.
func (c *Client) V2ScanSPDX(filePath string, metadata ...[]byte) (map[string]interface{}, error) {
	data, err := readFileBytes(filePath)
	if err != nil {
		return nil, err
	}

	path := "/scan/spdx"
	if len(metadata) > 0 && len(metadata[0]) > 0 {
		path += "?metadata=" + url.QueryEscape(string(metadata[0]))
	}

	respBody, err := c.DoRequestRawBody("POST", path, data, "application/json")
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// V2ScanCycloneDX uploads a CycloneDX document for scanning.
// An optional metadata parameter (JSON bytes) is sent as a query parameter.
func (c *Client) V2ScanCycloneDX(filePath string, metadata ...[]byte) (map[string]interface{}, error) {
	data, err := readFileBytes(filePath)
	if err != nil {
		return nil, err
	}

	path := "/scan/cyclonedx"
	if len(metadata) > 0 && len(metadata[0]) > 0 {
		path += "?metadata=" + url.QueryEscape(string(metadata[0]))
	}

	respBody, err := c.DoRequestRawBody("POST", path, data, "application/json")
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// V2ScanStatus retrieves the status of a scan.
func (c *Client) V2ScanStatus(scanID string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/scan/%s", url.PathEscape(scanID))
	return doV2Get(c, path)
}

// V2CloudLocators retrieves cloud resource locator templates for a vendor/product pair.
func (c *Client) V2CloudLocators(vendor, product string) (map[string]interface{}, error) {
	q := url.Values{}
	if vendor != "" {
		q.Set("vendor", vendor)
	}
	if product != "" {
		q.Set("product", product)
	}
	path := "/cloud-locators"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

// SnortSearchParams carries the optional filter knobs for V2SnortRulesSearch.
// All fields are optional; zero-valued slices and strings are skipped.
type SnortSearchParams struct {
	CveIDs           []string
	Sources          []string
	Techniques       []string // MITRE ATT&CK T-id (any of)
	Tactics          []string // MITRE ATT&CK TA-id (any of)
	Classtype        string
	Severity         string
	Protocol         string
	Action           string
	DstPort          string
	SrcPort          string
	Disabled         string // "true" / "false" / ""
	Q                string // free-text on msg + rawText
	AffectedProducts []string
	Tags             []string
	Since            string // RFC3339
	Until            string // RFC3339
	Sort             string // recent | severity | id
	Limit            int
	Offset           int
}

// V2SnortRules retrieves a CVE's Snort rules (per-CVE endpoint).
func (c *Client) V2SnortRules(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/snort-rules", url.PathEscape(id)))
}

// V2SnortRulesSearch performs a collection-wide search for Snort rules with
// expressive filters.
func (c *Client) V2SnortRulesSearch(p SnortSearchParams) (map[string]interface{}, error) {
	q := url.Values{}
	for _, v := range p.CveIDs {
		q.Add("cveId", v)
	}
	for _, v := range p.Sources {
		q.Add("source", v)
	}
	for _, v := range p.Techniques {
		q.Add("technique", v)
	}
	for _, v := range p.Tactics {
		q.Add("tactic", v)
	}
	for _, v := range p.AffectedProducts {
		q.Add("affectedProduct", v)
	}
	for _, v := range p.Tags {
		q.Add("tag", v)
	}
	for k, v := range map[string]string{
		"classtype": p.Classtype,
		"severity":  p.Severity,
		"protocol":  p.Protocol,
		"action":    p.Action,
		"dstPort":   p.DstPort,
		"srcPort":   p.SrcPort,
		"disabled":  p.Disabled,
		"q":         p.Q,
		"since":     p.Since,
		"until":     p.Until,
		"sort":      p.Sort,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	path := "/snort-rules"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

// YaraSearchParams carries the optional filter knobs for V2YaraRulesSearch.
type YaraSearchParams struct {
	CveIDs      []string
	Sources     []string
	RuleName    string
	Tags        []string
	Imports     []string
	Author      string
	Q           string
	MatchString string
	MatchMeta   string
	Since       string
	Until       string
	Sort        string // recent | name
	Limit       int
	Offset      int
}

// V2YaraRules retrieves a CVE's YARA rules (per-CVE endpoint).
func (c *Client) V2YaraRules(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/yara-rules", url.PathEscape(id)))
}

// V2YaraRulesSearch performs a collection-wide search for YARA rules.
func (c *Client) V2YaraRulesSearch(p YaraSearchParams) (map[string]interface{}, error) {
	q := url.Values{}
	for _, v := range p.CveIDs {
		q.Add("cveId", v)
	}
	for _, v := range p.Sources {
		q.Add("source", v)
	}
	for _, v := range p.Tags {
		q.Add("tag", v)
	}
	for _, v := range p.Imports {
		q.Add("imports", v)
	}
	for k, v := range map[string]string{
		"ruleName":    p.RuleName,
		"author":      p.Author,
		"q":           p.Q,
		"matchString": p.MatchString,
		"matchMeta":   p.MatchMeta,
		"since":       p.Since,
		"until":       p.Until,
		"sort":        p.Sort,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	path := "/yara-rules"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

// AttackTechniquesSearchParams carries the optional filter knobs for the
// MITRE ATT&CK collection endpoint.
type AttackTechniquesSearchParams struct {
	TechniqueIDs []string
	Tactics      []string
	CveIDs       []string
	Sources      []string
	CapecID      string
	Domain       string
	Subtechnique string
	DerivedBy    string
	Q            string
	Since        string
	Until        string
	Limit        int
	Offset       int
}

// V2AttackTechniques retrieves the ATT&CK technique mapping for a single CVE.
func (c *Client) V2AttackTechniques(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/attack-techniques", url.PathEscape(id)))
}

// V2AttackTechniquesSearch performs a collection-wide search for ATT&CK
// technique mappings across CVEs.
func (c *Client) V2AttackTechniquesSearch(p AttackTechniquesSearchParams) (map[string]interface{}, error) {
	q := url.Values{}
	for _, v := range p.TechniqueIDs {
		q.Add("techniqueId", v)
	}
	for _, v := range p.Tactics {
		q.Add("tactic", v)
	}
	for _, v := range p.CveIDs {
		q.Add("cveId", v)
	}
	for _, v := range p.Sources {
		q.Add("source", v)
	}
	for k, v := range map[string]string{
		"capecId":      p.CapecID,
		"domain":       p.Domain,
		"subtechnique": p.Subtechnique,
		"derivedBy":    p.DerivedBy,
		"q":            p.Q,
		"since":        p.Since,
		"until":        p.Until,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	path := "/attack-techniques"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

func readFileBytes(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return data, nil
}
