package vdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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

// ── SOC analyst surface ──────────────────────────────────────────────────

// V2VulnExploits — GET /v2/vuln/{id}/exploits.
func (c *Client) V2VulnExploits(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/exploits", url.PathEscape(id)))
}

// V2ExploitPoC — GET /v2/exploits/{exploitUuid}/poc. Returns raw bytes,
// the original filename (from Content-Disposition), and the SHA-256 hash
// (from X-Vulnetix-Sha256). The CLI uses these to write a file with a
// chain-of-custody-friendly name + integrity check.
func (c *Client) V2ExploitPoC(exploitUUID string) (body []byte, filename, sha256, originalURL string, err error) {
	path := fmt.Sprintf("/exploits/%s/poc", url.PathEscape(exploitUUID))
	urlStr := c.BaseURL + c.APIVersion + path
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("new request: %w", err)
	}
	if err := c.addAuthHeader(req); err != nil {
		return nil, "", "", "", err
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, "", "", "", err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", "", err
	}
	if resp.StatusCode != 200 {
		return nil, "", "", "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}
	cd := resp.Header.Get("Content-Disposition")
	if i := strings.Index(cd, `filename="`); i >= 0 {
		rest := cd[i+len(`filename="`):]
		if j := strings.Index(rest, `"`); j > 0 {
			filename = rest[:j]
		}
	}
	sha256 = resp.Header.Get("X-Vulnetix-Sha256")
	originalURL = resp.Header.Get("X-Vulnetix-Original-Url")
	return body, filename, sha256, originalURL, nil
}

// IOCSearchParams ─ GET /v2/iocs.
type IOCSearchParams struct {
	CveIDs     []string
	Countries  []string
	ASNs       []int
	Behavior   string
	Reputation string
	Since      string
	Limit      int
	Offset     int
	Format     string // json | stix
}

func (c *Client) V2VulnIOCs(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/iocs", url.PathEscape(id)))
}

// V2IOCsSearch returns the raw response body so the caller can switch on
// `format` (the STIX bundle is not JSON-shape compatible).
func (c *Client) V2IOCsSearch(p IOCSearchParams) ([]byte, string, error) {
	q := url.Values{}
	for _, v := range p.CveIDs {
		q.Add("cveId", v)
	}
	for _, v := range p.Countries {
		q.Add("country", v)
	}
	for _, v := range p.ASNs {
		q.Add("asn", fmt.Sprintf("%d", v))
	}
	if p.Behavior != "" {
		q.Set("behavior", p.Behavior)
	}
	if p.Reputation != "" {
		q.Set("reputation", p.Reputation)
	}
	if p.Since != "" {
		q.Set("since", p.Since)
	}
	if p.Format != "" {
		q.Set("format", p.Format)
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	path := "/iocs"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	body, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, "", err
	}
	return body, "application/json", nil
}

// V2VulnSightings — GET /v2/vuln/{id}/sightings.
func (c *Client) V2VulnSightings(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/sightings", url.PathEscape(id)))
}

// V2VulnVex — GET /v2/vuln/{id}/vex.
func (c *Client) V2VulnVex(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/vex", url.PathEscape(id)))
}

// VexSearchParams ─ GET /v2/vex.
type VexSearchParams struct {
	CveIDs   []string
	Status   string
	Supplier string
	Since    string
	Limit    int
	Offset   int
}

func (c *Client) V2VexSearch(p VexSearchParams) (map[string]interface{}, error) {
	q := url.Values{}
	for _, v := range p.CveIDs {
		q.Add("cveId", v)
	}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.Supplier != "" {
		q.Set("supplier", p.Supplier)
	}
	if p.Since != "" {
		q.Set("since", p.Since)
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	path := "/vex"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

// TriageParams ─ GET /v2/triage.
type TriageParams struct {
	MinEpss             *float64
	MinEpssPercentile   *float64
	MinCess             *float64
	MinCvss             *float64
	Severity            string
	InKev               string // "true" / "false" / ""
	KevSources          []string
	CWEs                []string
	Vendor              string
	Product             string
	Since               string
	WindowDays          int // 0 = unset; 1..30
	Sort                string
	Limit               int
	Offset              int
}

func (c *Client) V2Triage(p TriageParams) (map[string]interface{}, error) {
	q := url.Values{}
	if p.MinEpss != nil {
		q.Set("minEpss", fmt.Sprintf("%g", *p.MinEpss))
	}
	if p.MinEpssPercentile != nil {
		q.Set("minEpssPercentile", fmt.Sprintf("%g", *p.MinEpssPercentile))
	}
	if p.MinCess != nil {
		q.Set("minCess", fmt.Sprintf("%g", *p.MinCess))
	}
	if p.MinCvss != nil {
		q.Set("minCvss", fmt.Sprintf("%g", *p.MinCvss))
	}
	if p.Severity != "" {
		q.Set("severity", p.Severity)
	}
	if p.InKev != "" {
		q.Set("inKev", p.InKev)
	}
	for _, s := range p.KevSources {
		q.Add("kevSource", s)
	}
	for _, c := range p.CWEs {
		q.Add("cwe", c)
	}
	if p.Vendor != "" {
		q.Set("vendor", p.Vendor)
	}
	if p.Product != "" {
		q.Set("product", p.Product)
	}
	if p.Since != "" {
		q.Set("since", p.Since)
	}
	if p.WindowDays > 0 {
		q.Set("windowDays", fmt.Sprintf("%d", p.WindowDays))
	}
	if p.Sort != "" {
		q.Set("sort", p.Sort)
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	path := "/triage"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

// V2RawSources — GET /v2/raw/sources.
func (c *Client) V2RawSources() (map[string]interface{}, error) {
	return doV2Get(c, "/raw/sources")
}

// V2RawArchive — GET /v2/raw/{source}/{cveId}. Returns raw bytes +
// content-type + sha256.
func (c *Client) V2RawArchive(source, cveID string) (body []byte, contentType, sha256, r2Path string, err error) {
	path := fmt.Sprintf("/raw/%s/%s", url.PathEscape(source), url.PathEscape(cveID))
	urlStr := c.BaseURL + c.APIVersion + path
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("new request: %w", err)
	}
	if err := c.addAuthHeader(req); err != nil {
		return nil, "", "", "", err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, "", "", "", err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", "", err
	}
	if resp.StatusCode != 200 {
		return nil, "", "", "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}
	contentType = resp.Header.Get("Content-Type")
	sha256 = resp.Header.Get("X-Vulnetix-Sha256")
	r2Path = resp.Header.Get("X-Vulnetix-R2-Path")
	return body, contentType, sha256, r2Path, nil
}

// V2VulnNuclei — GET /v2/vuln/{id}/nuclei. The CLI calls without format for
// the JSON listing, then optionally re-fetches with format=yaml&first=true
// to print a single template body.
func (c *Client) V2VulnNuclei(id string) (map[string]interface{}, error) {
	return doV2Get(c, fmt.Sprintf("/vuln/%s/nuclei", url.PathEscape(id)))
}

// V2VulnNucleiYAML — GET /v2/vuln/{id}/nuclei?format=yaml. Returns the raw
// YAML body. With first=true, returns the first template alone.
func (c *Client) V2VulnNucleiYAML(id string, first bool) ([]byte, error) {
	q := url.Values{}
	q.Set("format", "yaml")
	if first {
		q.Set("first", "true")
	}
	path := fmt.Sprintf("/vuln/%s/nuclei?%s", url.PathEscape(id), q.Encode())
	return c.DoRequest("GET", path, nil)
}

// KevSearchParams ─ GET /v2/kev (the 4-source merged collection).
type KevSearchParams struct {
	CveIDs    []string
	Sources   []string // CISA | vulnetix | enisa | vulncheck (repeat for OR; default = all four)
	Reason    string
	Since     string
	Until     string
	DueBefore string
	DueAfter  string
	Vendor    string
	Product   string
	Sort      string // due | added | cve
	Limit     int
	Offset    int
}

func (c *Client) V2KevSearch(p KevSearchParams) (map[string]interface{}, error) {
	q := url.Values{}
	for _, v := range p.CveIDs {
		q.Add("cveId", v)
	}
	for _, v := range p.Sources {
		q.Add("source", v)
	}
	if p.Reason != "" {
		q.Set("reason", p.Reason)
	}
	if p.Since != "" {
		q.Set("since", p.Since)
	}
	if p.Until != "" {
		q.Set("until", p.Until)
	}
	if p.DueBefore != "" {
		q.Set("dueBefore", p.DueBefore)
	}
	if p.DueAfter != "" {
		q.Set("dueAfter", p.DueAfter)
	}
	if p.Vendor != "" {
		q.Set("vendor", p.Vendor)
	}
	if p.Product != "" {
		q.Set("product", p.Product)
	}
	if p.Sort != "" {
		q.Set("sort", p.Sort)
	}
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", p.Offset))
	}
	path := "/kev"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return doV2Get(c, path)
}

// TreeSitterCapture describes a named capture inside a tree-sitter query.
type TreeSitterCapture struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// TreeSitterPredicate describes a predicate or directive attached to a query
// (e.g. #eq?, #match?, #set!).
type TreeSitterPredicate struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	Negated bool     `json:"negated"`
	Args    []string `json:"args"`
}

// TreeSitterQuery is a single S-expression query derived from CVE/OSV data
// by vdb-manager. The CLI runs these against source files to determine
// reachability of a vulnerable pattern.
type TreeSitterQuery struct {
	VulnID      string                `json:"vulnId,omitempty"`
	Source      string                `json:"source,omitempty"`
	Ecosystems  []string              `json:"ecosystems,omitempty"`
	Language    string                `json:"language"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	QueryText   string                `json:"queryText"`
	QueryHash   string                `json:"queryHash,omitempty"`
	DerivedBy   string                `json:"derivedBy,omitempty"`
	CreatedAt   int64                 `json:"createdAt,omitempty"`
	Captures    []TreeSitterCapture   `json:"captures,omitempty"`
	Predicates  []TreeSitterPredicate `json:"predicates,omitempty"`
	Directives  []TreeSitterPredicate `json:"directives,omitempty"`
}

// TreeSitterFilters echoes the filter parameters back on the response.
type TreeSitterFilters struct {
	Language  string `json:"language,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	VulnID    string `json:"vulnId,omitempty"`
}

// TreeSitterResponse is the body of GET /vuln/{id}/tree-sitter.
type TreeSitterResponse struct {
	Identifier string            `json:"identifier"`
	Filters    TreeSitterFilters `json:"filters"`
	Queries    []TreeSitterQuery `json:"queries"`
}

// V2TreeSitterParams filters the tree-sitter query endpoint.
type V2TreeSitterParams struct {
	Language  string
	Ecosystem string
}

// V2TreeSitterQueries retrieves tree-sitter S-expression queries derived
// from the named vulnerability. Returns a typed response (unlike most v2
// helpers) because the scanner consumes the result programmatically.
func (c *Client) V2TreeSitterQueries(id string, p V2TreeSitterParams) (*TreeSitterResponse, error) {
	q := url.Values{}
	if p.Language != "" {
		q.Set("language", p.Language)
	}
	if p.Ecosystem != "" {
		q.Set("ecosystem", p.Ecosystem)
	}
	path := fmt.Sprintf("/vuln/%s/tree-sitter", url.PathEscape(id))
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var out TreeSitterResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("failed to parse tree-sitter response: %w", err)
	}
	return &out, nil
}

func readFileBytes(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return data, nil
}
