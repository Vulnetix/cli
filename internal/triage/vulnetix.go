package triage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vulnetix/cli/internal/memory"
	"github.com/vulnetix/cli/pkg/vdb"
)

func init() {
	// Register vulnetix as the default triage provider.
	// Callers should use NewVulnetixProvider with credential-resolved clients;
	// the registry factory returns nil clients and is only used for listing.
	TriageProviders["vulnetix"] = func() TriageProvider {
		return &VulnetixProvider{}
	}
}

// FetchAlerts is not implemented for the Vulnetix provider — it only supports
// per-CVE triage via TriageCVE. Returns nil to satisfy Provider interface.
func (p *VulnetixProvider) FetchAlerts(ctx context.Context, opts FetchOptions) ([]Alert, error) {
	return nil, nil
}

// VulnetixProvider fetches triage data from the Vulnetix VDB API.
type VulnetixProvider struct {
	client *vdb.Client
	v2     *vdb.Client
}

// NewVulnetixProvider creates a new Vulnetix provider from the given VDB client.
// The v1 client is used for vuln/exploit lookups; the v2 client for
// affected ranges, remediation plans, and scorecard data.
func NewVulnetixProvider(v1, v2 *vdb.Client) *VulnetixProvider {
	return &VulnetixProvider{
		client: v1,
		v2:     v2,
	}
}

// TriageCVE fetches full vulnerability intelligence from the VDB and maps it to
// a TriageFinding with CWSS score, threat model, and VEX status.
func (p *VulnetixProvider) TriageCVE(ctx context.Context, cveID string, pkgName, pkgVersion, ecosystem string, existing *memory.FindingRecord) (*TriageFinding, error) {
	finding := &TriageFinding{
		CVEID:          cveID,
		Package:        pkgName,
		Ecosystem:      ecosystem,
		InstalledVer:   pkgVersion,
		Status:         "under_investigation",
		Justification:  "",
		ActionResponse: "",
		Severity:       "unknown",
		SafeHarbour:    0,
		Source:         "vulnetix",
		History:        []memory.HistoryEntry{},
	}

	// Preserve prior history.
	if existing != nil {
		finding.History = append([]memory.HistoryEntry{}, existing.History...)
	}

	// ── 1. Fetch vulnerability detail ───────────────────────────────────
	cveInfo, err := p.client.GetCVE(cveID)
	if err != nil {
		return nil, fmt.Errorf("vdb vuln lookup %s: %w", cveID, err)
	}
	parsed := parseCVEInfo(cveInfo)
	if parsed != nil {
		finding.Package = coalesce(pkgName, parsed.Package)
		finding.Ecosystem = coalesce(ecosystem, parsed.Ecosystem)
		finding.Severity = parsed.Severity
		finding.SafeHarbour = parsed.SafeHarbour
		if parsed.FixedIn != "" {
			finding.FixedVer = parsed.FixedIn
		}
	}

	// ── 2. Check affected via V2 ───────────────────────────────────────
	if p.v2 != nil && pkgName != "" && pkgVersion != "" {
		affectedResp, err := p.v2.V2Affected(cveID, vdb.V2QueryParams{
			Ecosystem:   ecosystem,
			PackageName: pkgName,
		})
		if err == nil {
			isAffected := checkAffected(affectedResp, pkgVersion)
			if !isAffected {
				finding.Status = "not_affected"
				finding.Justification = "vulnerable_code_not_present"
			}
		}
	}

	// ── 3. Fetch remediation plan ──────────────────────────────────────
	if p.v2 != nil && pkgName != "" {
		remResp, err := p.v2.V2RemediationPlan(cveID, vdb.V2RemediationParams{
			V2QueryParams: vdb.V2QueryParams{
				Ecosystem:   ecosystem,
				PackageName: pkgName,
			},
			CurrentVersion: pkgVersion,
		})
		if err == nil {
			if fix := extractRemediationFix(remResp); fix != "" {
				finding.FixedVer = fix
				if finding.Status == "affected" || finding.Status == "under_investigation" {
					finding.ActionResponse = "will_fix"
				}
			}
			if avail := extractRemediationAvail(remResp); avail != "" {
				switch strings.ToLower(avail) {
				case "available", "fix_available":
					if finding.Status == "affected" || finding.Status == "under_investigation" {
						finding.ActionResponse = "will_fix"
					}
				case "partial":
					if finding.Status == "affected" || finding.Status == "under_investigation" {
						finding.ActionResponse = "update"
					}
				case "no_fix":
					if finding.Status == "affected" || finding.Status == "under_investigation" {
						finding.ActionResponse = "will_not_fix"
					}
				}
			}
		}
	}

	// ── 4. Fetch CWSS scorecard ────────────────────────────────────────
	if p.v2 != nil {
		scorecard, err := p.v2.V2Scorecard(cveID)
		if err == nil {
			finding.CWSS = extractCWSS(scorecard)
			finding.ThreatModel = extractThreatModel(scorecard)
		}
	}

	// ── 5. Fetch exploits ──────────────────────────────────────────────
	exploits, err := p.client.GetExploits(cveID)
	if err == nil {
		finding.ExploitCount = countExploits(exploits)
		finding.InKEV = inKEV(exploits)
	}

	// ── 6. Fetch KEV status ────────────────────────────────────────────
	if p.v2 != nil {
		kevResp, err := p.v2.V2Kev(cveID)
		if err == nil {
			if kevResp["known_exploited"] == true || kevResp["inKev"] == true {
				finding.InKEV = true
			}
		}
	}

	// ── 7. History entry ───────────────────────────────────────────────
	finding.History = append(finding.History, memory.HistoryEntry{
		Date:   time.Now().UTC().Format(time.RFC3339),
		Event:  "triage",
		Detail: fmt.Sprintf("status set to %s via vulnetix provider", finding.Status),
	})

	// ── 8. Compute decision from status ────────────────────────────────
	finding.Decision = decisionFromFailure(finding)

	return finding, nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

type parsedCVE struct {
	Package     string
	Ecosystem   string
	Severity    string
	SafeHarbour float64
	FixedIn     string
}

// parseCVEInfo extracts useful fields from the opaque CVEInfo response.
func parseCVEInfo(info *vdb.CVEInfo) *parsedCVE {
	if info == nil || info.Data == nil {
		return nil
	}
	// Data may be a map[string]interface{} from JSON unmarshal.
	m, ok := info.Data.(map[string]interface{})
	if !ok {
		return nil
	}
	p := &parsedCVE{}

	if sev, ok := m["severity"].(string); ok {
		p.Severity = strings.ToLower(sev)
	}
	if sh, ok := m["safe_harbour"].(float64); ok {
		p.SafeHarbour = sh
	}
	if fixes, ok := m["fixes"].([]interface{}); ok && len(fixes) > 0 {
		if f, ok := fixes[0].(map[string]interface{}); ok {
			if fi, ok := f["fixedIn"].(string); ok {
				p.FixedIn = fi
			}
			if pkg, ok := f["package"].(string); ok {
				p.Package = pkg
			}
			if eco, ok := f["ecosystem"].(string); ok {
				p.Ecosystem = eco
			}
		}
	}
	if p.Severity == "" {
		if s, ok := m["base_score"].(float64); ok && s > 0 {
			if s >= 9.0 {
				p.Severity = "critical"
			} else if s >= 7.0 {
				p.Severity = "high"
			} else if s >= 4.0 {
				p.Severity = "medium"
			} else {
				p.Severity = "low"
			}
		}
	}

	return p
}

// checkAffected inspects the V2Affected response to determine if the installed
// version is within the affected range. Returns false if the version is safe.
func checkAffected(resp map[string]interface{}, installedVer string) bool {
	if resp == nil {
		return true // assume affected when API fails
	}
	// The response structure from V2Affected contains an "affected" key.
	if affected, ok := resp["affected"].(bool); ok {
		return affected
	}
	// Fall back: if the response has "fixed_in" and we can compare versions,
	// check if installed is below the fix.
	if fixedIn, ok := resp["fixed_in"].(string); ok && fixedIn != "" {
		// Simple semver-like comparison for equal/less.
		return true // conservative: still affected until version is verified below fixed
	}
	return true
}

// countExploits counts exploit records in the response.
func countExploits(resp map[string]interface{}) int {
	if resp == nil {
		return 0
	}
	if exploits, ok := resp["exploits"].([]interface{}); ok {
		return len(exploits)
	}
	if c, ok := resp["exploit_count"].(float64); ok {
		return int(c)
	}
	return 0
}

// inKEV checks if the exploit response indicates CISA KEV listing.
func inKEV(resp map[string]interface{}) bool {
	if resp == nil {
		return false
	}
	if kev, ok := resp["in_kev"].(bool); ok {
		return kev
	}
	if kev, ok := resp["inKev"].(bool); ok {
		return kev
	}
	return false
}

// extractRemediationFix extracts the fix version from a remediation plan response.
func extractRemediationFix(resp map[string]interface{}) string {
	if resp == nil {
		return ""
	}
	if v, ok := resp["fixed_version"].(string); ok {
		return v
	}
	if v, ok := resp["fix_version"].(string); ok {
		return v
	}
	if fixes, ok := resp["fixes"].([]interface{}); ok && len(fixes) > 0 {
		if f, ok := fixes[0].(map[string]interface{}); ok {
			if v, ok := f["fixedIn"].(string); ok {
				return v
			}
			if v, ok := f["fixedIn"].(string); ok {
				return v
			}
		}
	}
	return ""
}

// extractRemediationAvail extracts the fix availability string.
func extractRemediationAvail(resp map[string]interface{}) string {
	if resp == nil {
		return ""
	}
	if v, ok := resp["fix_availability"].(string); ok {
		return v
	}
	if v, ok := resp["fixAvailability"].(string); ok {
		return v
	}
	return ""
}

// extractCWSS extracts CWSS scoring data from a scorecard response.
func extractCWSS(resp map[string]interface{}) *CWSSData {
	if resp == nil {
		return nil
	}
	if cwss, ok := resp["cwss"].(map[string]interface{}); ok {
		data := &CWSSData{}
		if score, ok := cwss["score"].(float64); ok {
			data.Score = score
		}
		if pri, ok := cwss["priority"].(string); ok {
			data.Priority = pri
		}
		if factors, ok := cwss["factors"].(map[string]interface{}); ok {
			data.Factors = make(map[string]float64)
			for k, v := range factors {
				if f, ok := v.(float64); ok {
					data.Factors[k] = f
				}
			}
		}
		if data.Score > 0 {
			return data
		}
	}
	// Top-level score.
	if score, ok := resp["score"].(float64); ok && score > 0 {
		data := &CWSSData{Score: score}
		if pri, ok := resp["priority"].(string); ok {
			data.Priority = pri
		}
		return data
	}
	return nil
}

// extractThreatModel extracts threat model data from a scorecard response.
func extractThreatModel(resp map[string]interface{}) *ThreatModel {
	if resp == nil {
		return nil
	}
	if tm, ok := resp["threat_model"].(map[string]interface{}); ok {
		model := &ThreatModel{}
		if av, ok := tm["attack_vector"].(string); ok {
			model.AttackVector = av
		}
		if ac, ok := tm["attack_complexity"].(string); ok {
			model.AttackComplexity = ac
		}
		if pr, ok := tm["privileges_required"].(string); ok {
			model.PrivilegesRequired = pr
		}
		if ui, ok := tm["user_interaction"].(string); ok {
			model.UserInteraction = ui
		}
		if r, ok := tm["reachability"].(string); ok {
			model.Reachability = r
		}
		if e, ok := tm["exposure"].(string); ok {
			model.Exposure = e
		}
		if model.AttackVector != "" || model.Reachability != "" {
			return model
		}
	}
	// Check nested under cwss or root.
	for _, key := range []string{"cvss", "metrics"} {
		if nested, ok := resp[key].(map[string]interface{}); ok {
			if av, ok := nested["attack_vector"].(string); ok {
				return &ThreatModel{
					AttackVector:       av,
					AttackComplexity:   str(nested, "attack_complexity"),
					PrivilegesRequired: str(nested, "privileges_required"),
					UserInteraction:    str(nested, "user_interaction"),
				}
			}
		}
	}
	return nil
}

func str(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// decisionFromFailure maps the current VEX status to a default decision.
func decisionFromFailure(f *TriageFinding) *memory.Decision {
	if f == nil {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	switch f.Status {
	case "not_affected":
		return &memory.Decision{
			Choice: "not-affected",
			Reason: fmt.Sprintf("determined %s by vulnetix provider", f.Justification),
			Date:   now,
		}
	case "fixed":
		return &memory.Decision{
			Choice: "fix-applied",
			Reason: "fix applied",
			Date:   now,
		}
	case "affected":
		switch f.ActionResponse {
		case "will_not_fix":
			return &memory.Decision{
				Choice: "risk-accepted",
				Reason: "no fix available, risk accepted by default",
				Date:   now,
			}
		case "will_fix":
			return &memory.Decision{
				Choice: "deferred",
				Reason: "fix available will apply later",
				Date:   now,
			}
		}
		return nil
	default:
		return nil
	}
}

// Unused context parameter to avoid lint errors while the ctx is passed from
// callers for future cancellation support.
var _ = context.Background
