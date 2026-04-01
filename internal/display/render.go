package display

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/vulnetix/cli/internal/tui"
)

// RenderVulnDetail renders a single vulnerability detail view.
// Handles both flat vuln objects and CVE 5.0 JSON format (array of records with containers/cveMetadata).
func RenderVulnDetail(data any, ctx *Context) string {
	// Handle array response: merge fields from all records to get the richest view.
	// CVE data often has multiple advisory records; the first may lack CVSS but have KEV/EPSS.
	if arr, ok := data.([]any); ok && len(arr) > 0 {
		merged := mergeVulnRecords(arr)
		return RenderVulnDetail(merged, ctx)
	}

	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}

	t := ctx.Term
	var b strings.Builder

	// --- Extract fields from CVE 5.0 format or flat format ---

	id := ToStringVal(m["id"])
	if id == "" {
		id = ToStringVal(m["cveId"])
	}
	if id == "" {
		if meta, ok := m["cveMetadata"].(map[string]any); ok {
			id = ToStringVal(meta["cveId"])
		}
	}

	description := ToStringVal(m["description"])
	severity := ToStringVal(m["severity"])
	if severity == "" {
		severity = ToStringVal(m["baseSeverity"])
	}
	var baseScore float64
	var vector, cvssVersion string
	var epss, epssPercentile float64
	var cwes []string
	var refs []map[string]any
	var published, modified string
	var kevPresent bool
	var kevName, kevAction, kevDueDate string
	var ssvcDecision, ssvcPriority string
	var exploitLevel string

	// CVE 5.0 format: extract from containers
	if containers, ok := m["containers"].(map[string]any); ok {
		// --- CNA container: description, metrics, CWEs, references ---
		if cna, ok := containers["cna"].(map[string]any); ok {
			if description == "" {
				if descs, ok := cna["descriptions"].([]any); ok && len(descs) > 0 {
					if d, ok := descs[0].(map[string]any); ok {
						description = ToStringVal(d["value"])
					}
				}
			}
			extractCVSS(cna, &baseScore, &severity, &vector, &cvssVersion)
			cwes = extractCWEs(cna)
			refs = extractRefs(cna)
		}

		// --- ADP containers: VVD enrichment with EPSS, KEV, SSVC, exploitation ---
		if adpList, ok := containers["adp"].([]any); ok {
			for _, adpItem := range adpList {
				adp, ok := adpItem.(map[string]any)
				if !ok {
					continue
				}

				// Also extract CVSS from ADP if CNA didn't have it
				if baseScore == 0 {
					extractCVSS(adp, &baseScore, &severity, &vector, &cvssVersion)
				}

				// EPSS
				if xEpss, ok := adp["x_epss"].(map[string]any); ok {
					epss = ToFloat64(xEpss["score"])
					epssPercentile = ToFloat64(xEpss["percentile"])
				}

				// KEV
				if xKev, ok := adp["x_kev"].(map[string]any); ok {
					kevPresent = true
					kevName = ToStringVal(xKev["vulnerabilityName"])
					kevAction = ToStringVal(xKev["requiredAction"])
					kevDueDate = ToStringVal(xKev["dueDate"])
					if len(cwes) == 0 {
						if kevCWEs, ok := xKev["cwes"].([]any); ok {
							for _, c := range kevCWEs {
								cwes = append(cwes, ToStringVal(c))
							}
						}
					}
				}

				// SSVC
				if xSSVC, ok := adp["x_ssvc"].(map[string]any); ok {
					ssvcDecision = ToStringVal(xSSVC["decision"])
					ssvcPriority = ToStringVal(xSSVC["priority"])
				}

				// Exploitation maturity
				if xExploit, ok := adp["x_exploitationMaturity"].(map[string]any); ok {
					exploitLevel = ToStringVal(xExploit["level"])
				}

				// ADP-level description fallback
				if description == "" {
					if descs, ok := adp["descriptions"].([]any); ok && len(descs) > 0 {
						if d, ok := descs[0].(map[string]any); ok {
							description = ToStringVal(d["value"])
						}
					}
				}

				// ADP-level references fallback
				if len(refs) == 0 {
					refs = extractRefs(adp)
				}
			}
		}
	}

	// Dates from cveMetadata
	if meta, ok := m["cveMetadata"].(map[string]any); ok {
		published = ToStringVal(meta["datePublished"])
		modified = ToStringVal(meta["dateUpdated"])
	}
	if published == "" {
		published = ToStringVal(m["published"])
	}
	if modified == "" {
		modified = ToStringVal(m["modified"])
	}

	// Flat format fallbacks
	if baseScore == 0 {
		baseScore = ToFloat64(m["baseScore"])
	}
	if vector == "" {
		vector = ToStringVal(m["vector"])
	}
	if epss == 0 {
		epss = ToFloat64(m["epssScore"])
	}

	// --- Render ---

	// Header: CVE ID + severity badge
	header := Bold(t, id)
	if severity != "" {
		header += "  " + SeverityBadge(t, strings.ToLower(severity))
	}
	b.WriteString("\n" + header + "\n")

	// Title from KEV if available
	if kevName != "" {
		b.WriteString(Muted(t, kevName) + "\n")
	}

	// Description
	if description != "" {
		b.WriteString("\n" + wordWrap(description, t.Width-2) + "\n")
	}

	// Scores section
	hasScores := baseScore > 0 || epss > 0 || ssvcDecision != "" || exploitLevel != ""
	if hasScores {
		b.WriteString("\n" + Subheader(t, "Scores") + "\n")

		barWidth := 20
		if t.Width < 60 {
			barWidth = 12
		}

		if baseScore > 0 {
			scoreLabel := fmt.Sprintf("%.1f/10", baseScore)
			if cvssVersion != "" {
				scoreLabel += " (" + cvssVersion + ")"
			}
			// Colorize score label by severity
			styled := scoreLabel
			if severity != "" && t.HasColor() {
				color := tui.SeverityColor(strings.ToLower(severity))
				styled = lipgloss.NewStyle().Foreground(color).Render(scoreLabel)
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s\n",
				Label(t, PadRight("CVSS:", 12)),
				Bar(t, int(baseScore*10), 100, barWidth),
				styled))
		}

		if epss > 0 {
			pctLabel := fmt.Sprintf("%.4f", epss)
			if epssPercentile > 0 {
				pctLabel += fmt.Sprintf("  (%.1f%% percentile)", epssPercentile*100)
			}
			// Color EPSS: red if ≥0.7, orange if ≥0.3
			styledEpss := pctLabel
			if t.HasColor() {
				if epss >= 0.7 {
					styledEpss = lipgloss.NewStyle().Foreground(tui.ColorError).Render(pctLabel)
				} else if epss >= 0.3 {
					styledEpss = lipgloss.NewStyle().Foreground(tui.ColorHigh).Render(pctLabel)
				}
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s\n",
				Label(t, PadRight("EPSS:", 12)),
				Bar(t, int(epss*100), 100, barWidth),
				styledEpss))
		}

		if v, ok := m["cessScore"]; ok && ToFloat64(v) > 0 {
			cess := ToFloat64(v)
			b.WriteString(fmt.Sprintf("  %s %s  %s\n",
				Label(t, PadRight("CESS:", 12)),
				Bar(t, int(cess*100), 100, barWidth),
				fmt.Sprintf("%.4f", cess)))
		}

		if ssvcDecision != "" {
			ssvcStr := ssvcDecision
			if ssvcPriority != "" {
				ssvcStr += " (" + ssvcPriority + ")"
			}
			styledSSVC := ssvcStr
			if t.HasColor() {
				var ssvcColor lipgloss.Color
				switch strings.ToLower(ssvcDecision) {
				case "act":
					ssvcColor = tui.ColorCritical
				case "attend":
					ssvcColor = tui.ColorHigh
				case "track*":
					ssvcColor = tui.ColorMedium
				default:
					ssvcColor = tui.ColorInfo
				}
				styledSSVC = lipgloss.NewStyle().Foreground(ssvcColor).Render(ssvcStr)
			}
			b.WriteString(fmt.Sprintf("  %s %s\n", Label(t, PadRight("SSVC:", 12)), styledSSVC))
		}

		if exploitLevel != "" {
			styledExploit := exploitLevel
			if t.HasColor() {
				var exColor lipgloss.Color
				switch strings.ToUpper(exploitLevel) {
				case "ACTIVE":
					exColor = tui.ColorCritical
				case "HIGH":
					exColor = tui.ColorHigh
				case "POC", "AVAILABLE":
					exColor = tui.ColorMedium
				default:
					exColor = tui.ColorInfo
				}
				styledExploit = lipgloss.NewStyle().Foreground(exColor).Render(exploitLevel)
			}
			b.WriteString(fmt.Sprintf("  %s %s\n", Label(t, PadRight("Exploitation:", 12)), styledExploit))
		}
	}

	// Dates & vector
	var datePairs []KVPair
	if published != "" {
		datePairs = append(datePairs, KVPair{Key: "Published", Value: published})
	}
	if modified != "" {
		datePairs = append(datePairs, KVPair{Key: "Modified", Value: modified})
	}
	if vector != "" {
		datePairs = append(datePairs, KVPair{Key: "Vector", Value: Muted(t, vector)})
	}
	if len(datePairs) > 0 {
		b.WriteString("\n" + KeyValue(t, datePairs) + "\n")
	}

	// KEV section
	if kevPresent {
		b.WriteString("\n" + Subheader(t, "CISA KEV") + "  " + ErrorStyle(t, "KNOWN EXPLOITED") + "\n")
		var kevPairs []KVPair
		if kevDueDate != "" {
			kevPairs = append(kevPairs, KVPair{Key: "Due Date", Value: kevDueDate, ValueStyle: func(s string) string { return ErrorStyle(t, s) }})
		}
		if kevAction != "" {
			kevPairs = append(kevPairs, KVPair{Key: "Required Action", Value: wordWrap(kevAction, t.Width-20)})
		}
		if len(kevPairs) > 0 {
			b.WriteString(KeyValue(t, kevPairs) + "\n")
		}
	}

	// CWEs
	if len(cwes) == 0 {
		if cweList, ok := m["cwes"].([]any); ok {
			for _, c := range cweList {
				cwes = append(cwes, ToStringVal(c))
			}
		}
	}
	if len(cwes) > 0 {
		// Deduplicate
		seen := make(map[string]bool)
		unique := cwes[:0]
		for _, c := range cwes {
			if !seen[c] {
				seen[c] = true
				unique = append(unique, c)
			}
		}
		b.WriteString("\n" + Subheader(t, "CWEs") + "\n")
		b.WriteString(BulletList(t, unique) + "\n")
	}

	// References
	if len(refs) == 0 {
		if refList, ok := m["references"].([]any); ok {
			for _, r := range refList {
				if rm, ok := r.(map[string]any); ok {
					refs = append(refs, rm)
				}
			}
		}
	}
	if len(refs) > 0 {
		b.WriteString("\n" + Subheader(t, "References") + "\n")
		maxRefs := 10
		if len(refs) < maxRefs {
			maxRefs = len(refs)
		}
		items := make([]string, 0, maxRefs)
		for i := 0; i < maxRefs; i++ {
			url := ToStringVal(refs[i]["url"])
			items = append(items, Truncate(url, t.Width-6))
		}
		b.WriteString(BulletList(t, items) + "\n")
		if len(refs) > maxRefs {
			b.WriteString(Muted(t, fmt.Sprintf("  ... and %d more", len(refs)-maxRefs)) + "\n")
		}
	}

	return b.String()
}

// extractCVSS extracts CVSS score, severity, vector from a container (cna or adp).
func extractCVSS(container map[string]any, baseScore *float64, severity *string, vector *string, version *string) {
	metrics, ok := container["metrics"].([]any)
	if !ok {
		return
	}
	for _, metric := range metrics {
		mm, ok := metric.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"} {
			cvss, ok := mm[key].(map[string]any)
			if !ok {
				continue
			}
			if bs := ToFloat64(cvss["baseScore"]); bs > 0 && *baseScore == 0 {
				*baseScore = bs
			}
			if s := ToStringVal(cvss["baseSeverity"]); s != "" && *severity == "" {
				*severity = s
			}
			if v := ToStringVal(cvss["vectorString"]); v != "" && *vector == "" {
				*vector = v
			}
			if *version == "" {
				switch key {
				case "cvssV4_0":
					*version = "CVSS 4.0"
				case "cvssV3_1":
					*version = "CVSS 3.1"
				case "cvssV3_0":
					*version = "CVSS 3.0"
				case "cvssV2_0":
					*version = "CVSS 2.0"
				}
			}
			return
		}
	}
}

// extractCWEs extracts CWE IDs from a container's problemTypes.
func extractCWEs(container map[string]any) []string {
	var cwes []string
	problemTypes, ok := container["problemTypes"].([]any)
	if !ok {
		return cwes
	}
	for _, pt := range problemTypes {
		ptm, ok := pt.(map[string]any)
		if !ok {
			continue
		}
		descs, ok := ptm["descriptions"].([]any)
		if !ok {
			continue
		}
		for _, d := range descs {
			if dm, ok := d.(map[string]any); ok {
				if cweID := ToStringVal(dm["cweId"]); cweID != "" {
					cwes = append(cwes, cweID)
				}
			}
		}
	}
	return cwes
}

// extractRefs extracts reference URLs from a container.
func extractRefs(container map[string]any) []map[string]any {
	var refs []map[string]any
	refList, ok := container["references"].([]any)
	if !ok {
		return refs
	}
	for _, r := range refList {
		if rm, ok := r.(map[string]any); ok {
			refs = append(refs, rm)
		}
	}
	return refs
}

// mergeVulnRecords combines multiple CVE 5.0 records into a single map
// by using the first record as base and merging in containers from all others.
// This ensures we get CVSS from one ADP, EPSS from another, KEV from a third, etc.
func mergeVulnRecords(arr []any) map[string]any {
	if len(arr) == 0 {
		return nil
	}
	first, ok := arr[0].(map[string]any)
	if !ok {
		return nil
	}

	// Start with the first record's containers
	containers, _ := first["containers"].(map[string]any)
	if containers == nil {
		return first
	}

	// Collect all ADP and CNA containers from all records
	allADP, _ := containers["adp"].([]any)
	allCNA, _ := containers["cna"].(map[string]any)

	for _, item := range arr[1:] {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		c, ok := m["containers"].(map[string]any)
		if !ok {
			continue
		}
		// Merge ADP entries
		if adpList, ok := c["adp"].([]any); ok {
			allADP = append(allADP, adpList...)
		}
		// Use first CNA that has metrics if ours doesn't
		if allCNA != nil {
			if _, hasMetrics := allCNA["metrics"]; !hasMetrics {
				if cna, ok := c["cna"].(map[string]any); ok {
					if _, has := cna["metrics"]; has {
						allCNA = cna
					}
				}
			}
		} else if cna, ok := c["cna"].(map[string]any); ok {
			allCNA = cna
		}
	}

	// Rebuild merged record
	merged := make(map[string]any)
	for k, v := range first {
		merged[k] = v
	}
	mergedContainers := make(map[string]any)
	if allCNA != nil {
		mergedContainers["cna"] = allCNA
	}
	if len(allADP) > 0 {
		mergedContainers["adp"] = allADP
	}
	merged["containers"] = mergedContainers
	return merged
}

// RenderSummary renders the VDB database summary.
func RenderSummary(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	b.WriteString(Header(t, "VDB Database Summary"))

	// Database Coverage
	if db, ok := m["database"].(map[string]any); ok {
		b.WriteString("\n" + Subheader(t, "Database Coverage") + "\n")
		b.WriteString(KeyValue(t, []KVPair{
			{Key: "Total advisories", Value: FormatNumber(ToIntVal(db["totalRows"]))},
			{Key: "Distinct Vuln IDs", Value: FormatNumber(ToIntVal(db["distinctCveIds"]))},
			{Key: "Total exploits", Value: FormatNumber(ToIntVal(db["totalExploits"]))},
			{Key: "Malicious packages", Value: FormatNumber(ToIntVal(db["maliciousPackages"]))},
			{Key: "With exploits", Value: FormatNumber(ToIntVal(db["cvesWithExploits"]))},
			{Key: "Total references", Value: FormatNumber(ToIntVal(db["totalReferences"]))},
			{Key: "Distinct ref URLs", Value: FormatNumber(ToIntVal(db["distinctReferenceUrls"]))},
			{Key: "KEV entries", Value: FormatNumber(ToIntVal(db["totalKev"]))},
		}) + "\n")
	}

	// Severity Distribution
	if sev, ok := m["severity"].(map[string]any); ok {
		b.WriteString("\n" + Subheader(t, "Severity Distribution") + "\n")
		total := ToIntVal(sev["critical"]) + ToIntVal(sev["high"]) + ToIntVal(sev["medium"]) + ToIntVal(sev["low"]) + ToIntVal(sev["none"])
		barWidth := 30
		if t.Width < 60 {
			barWidth = 15
		}

		type sevEntry struct {
			name string
			key  string
		}
		sevLevels := []sevEntry{
			{"Critical", "critical"},
			{"High", "high"},
			{"Medium", "medium"},
			{"Low", "low"},
			{"None", "none"},
		}

		for _, sl := range sevLevels {
			count := ToIntVal(sev[sl.key])
			pct := ""
			if total > 0 {
				pct = Percentage(count, total)
			}
			bar := Bar(t, count, total, barWidth)
			labelText := PadRight(sl.name, 10)
			if t.HasColor() {
				color := tui.SeverityColor(sl.key)
				labelText = lipgloss.NewStyle().Foreground(color).Render(labelText)
			}
			numStr := PadLeft(FormatNumber(count), 10)
			b.WriteString(fmt.Sprintf("  %s %s %s  %s\n", labelText, bar, numStr, Muted(t, pct)))
		}
	}

	// Enrichment Coverage
	if cov, ok := m["coverage"].(map[string]any); ok {
		b.WriteString("\n" + Subheader(t, "Enrichment Coverage") + "\n")
		pairs := []KVPair{
			{Key: "With CVSS", Value: FormatNumber(ToIntVal(cov["withCvss"]))},
			{Key: "With EPSS", Value: FormatNumber(ToIntVal(cov["withEpss"]))},
			{Key: "With Coalition ESS", Value: FormatNumber(ToIntVal(cov["withCess"]))},
			{Key: "With CWE", Value: FormatNumber(ToIntVal(cov["withCwe"]))},
			{Key: "With CAPEC", Value: FormatNumber(ToIntVal(cov["withCapec"]))},
			{Key: "With SSVC", Value: FormatNumber(ToIntVal(cov["withSsvc"]))},
			{Key: "No references", Value: FormatNumber(ToIntVal(cov["noReferences"]))},
		}
		if avg, ok := cov["averageEpss"].(float64); ok {
			pairs = append(pairs, KVPair{Key: "Average EPSS", Value: FormatFloat(avg, 6)})
		}
		pairs = append(pairs, KVPair{Key: "High EPSS (≥0.7)", Value: FormatNumber(ToIntVal(cov["highEpss"]))})
		b.WriteString(KeyValue(t, pairs) + "\n")
	}

	// Top CWEs
	if cwes, ok := m["topCWEs"].([]any); ok && len(cwes) > 0 {
		b.WriteString("\n" + Subheader(t, "Top CWEs") + "\n")
		items := make([]string, 0, len(cwes))
		for _, item := range cwes {
			if cm, ok := item.(map[string]any); ok {
				items = append(items, fmt.Sprintf("%s %s",
					PadRight(ToStringVal(cm["cweId"]), 12),
					PadLeft(FormatNumber(ToIntVal(cm["count"]))+" advisories", 20)))
			}
		}
		b.WriteString(NumberedList(t, items) + "\n")
	}

	// Top Vendors
	if vendors, ok := m["topVendors"].([]any); ok && len(vendors) > 0 {
		b.WriteString("\n" + Subheader(t, "Top Vendors") + "\n")
		items := make([]string, 0, len(vendors))
		for _, item := range vendors {
			if vm, ok := item.(map[string]any); ok {
				items = append(items, fmt.Sprintf("%s %s",
					PadRight(Truncate(ToStringVal(vm["vendor"]), 20), 20),
					PadLeft(FormatNumber(ToIntVal(vm["count"]))+" advisories", 20)))
			}
		}
		b.WriteString(NumberedList(t, items) + "\n")
	}

	return b.String()
}

// RenderStatus renders VDB status/health information.
func RenderStatus(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	b.WriteString(Header(t, "VDB Status"))

	// CLI info
	if cli, ok := m["cli"].(map[string]any); ok {
		b.WriteString("\n" + Subheader(t, "CLI") + "\n")
		pairs := []KVPair{
			{Key: "Version", Value: ToStringVal(cli["version"])},
			{Key: "Commit", Value: ToStringVal(cli["commit"])},
			{Key: "Build Date", Value: ToStringVal(cli["buildDate"])},
			{Key: "Go", Value: ToStringVal(cli["goVersion"])},
			{Key: "Platform", Value: ToStringVal(cli["platform"])},
		}
		b.WriteString(KeyValue(t, pairs) + "\n")
	}

	// OAS URL
	if oas := ToStringVal(m["oasUrl"]); oas != "" {
		b.WriteString("\n" + Subheader(t, "OpenAPI Spec") + "\n")
		b.WriteString("  " + Accent(t, oas) + "\n")
	}

	// API Health
	if health, ok := m["health"].(map[string]any); ok {
		b.WriteString("\n" + Subheader(t, "API Health") + "\n")
		status := ToStringVal(health["status"])
		mark := CheckMark(t)
		if status != "ok" && status != "healthy" {
			mark = CrossMark(t)
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, status))
		// Show additional health fields
		for k, v := range health {
			if k == "status" {
				continue
			}
			b.WriteString(fmt.Sprintf("  %s %s\n", Label(t, k+":"), ToStringVal(v)))
		}
	}

	// Auth
	if authInfo, ok := m["auth"].(map[string]any); ok {
		b.WriteString("\n" + Subheader(t, "Authentication") + "\n")
		status := ToStringVal(authInfo["status"])
		mark := CheckMark(t)
		if !strings.HasPrefix(status, "ok") {
			mark = CrossMark(t)
		}
		pairs := []KVPair{
			{Key: "Status", Value: mark + " " + status},
			{Key: "Method", Value: ToStringVal(authInfo["method"])},
			{Key: "Source", Value: ToStringVal(authInfo["source"])},
		}
		if orgID := ToStringVal(authInfo["org_id"]); orgID != "" {
			pairs = append(pairs, KVPair{Key: "Org ID", Value: orgID})
		}
		b.WriteString(KeyValue(t, pairs) + "\n")
	}

	return b.String()
}

// RenderEcosystems renders the ecosystems list.
func RenderEcosystems(ecosystems []any, ctx *Context) string {
	t := ctx.Term
	var b strings.Builder

	b.WriteString("\n" + CountHeader(t, len(ecosystems), "ecosystems") + "\n\n")

	items := make([]string, 0, len(ecosystems))
	for _, eco := range ecosystems {
		if em, ok := eco.(map[string]any); ok {
			name := ToStringVal(em["name"])
			count := ToIntVal(em["count"])
			items = append(items, fmt.Sprintf("%s %s",
				PadRight(name, 20),
				Muted(t, FormatNumber(count)+" packages")))
		}
	}
	b.WriteString(BulletList(t, items))
	return b.String()
}

// RenderExploits renders exploit data for a vulnerability.
// Handles both: exploits[] array present (pro) and summary-only (community).
func RenderExploits(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	if id == "" {
		id = ToStringVal(m["id"])
	}
	exploitCount := ToIntVal(m["exploitCount"])
	sightingCount := ToIntVal(m["sightingCount"])
	totalCount := ToIntVal(m["count"])

	b.WriteString("\n" + Bold(t, "Exploits for "+id) + "\n")
	if totalCount > 0 || exploitCount > 0 {
		parts := []string{}
		if exploitCount > 0 {
			parts = append(parts, fmt.Sprintf("%s exploits", FormatNumber(exploitCount)))
		}
		if sightingCount > 0 {
			parts = append(parts, fmt.Sprintf("%s sightings", FormatNumber(sightingCount)))
		}
		if len(parts) == 0 {
			parts = append(parts, fmt.Sprintf("%s total", FormatNumber(totalCount)))
		}
		b.WriteString(Muted(t, "  "+strings.Join(parts, ", ")) + "\n")
	}

	// Summary breakdown (community mode)
	if summary, ok := m["summary"].(map[string]any); ok {
		b.WriteString("\n" + Subheader(t, "Source Breakdown") + "\n")
		// Sort by count descending
		type kv struct {
			k string
			v int
		}
		var sorted []kv
		for k, v := range summary {
			c := ToIntVal(v)
			if c > 0 {
				sorted = append(sorted, kv{k, c})
			}
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
		for _, item := range sorted {
			b.WriteString(fmt.Sprintf("  %s %s\n", PadRight(item.k, 20), Accent(t, FormatNumber(item.v))))
		}
	}

	// Detailed exploits array (pro mode)
	if exploits, ok := m["exploits"].([]any); ok && len(exploits) > 0 {
		b.WriteString("\n" + Subheader(t, "Exploits") + "\n")
		for i, exp := range exploits {
			if em, ok := exp.(map[string]any); ok {
				source := ToStringVal(em["source"])
				expType := ToStringVal(em["type"])
				maturity := ToStringVal(em["maturity"])
				url := ToStringVal(em["url"])
				name := ToStringVal(em["name"])

				prefix := fmt.Sprintf("  %d.", i+1)
				if name != "" {
					b.WriteString(fmt.Sprintf("%s %s\n", prefix, Bold(t, name)))
				} else if url != "" {
					b.WriteString(fmt.Sprintf("%s %s\n", prefix, Truncate(url, t.Width-len(prefix)-2)))
				}

				meta := []string{}
				if source != "" {
					meta = append(meta, Accent(t, source))
				}
				if expType != "" {
					meta = append(meta, expType)
				}
				if maturity != "" {
					meta = append(meta, maturity)
				}
				if len(meta) > 0 {
					b.WriteString("     " + strings.Join(meta, " · ") + "\n")
				}
			}
		}
	}

	return b.String()
}

// RenderExploitSearch renders exploit search results.
func RenderExploitSearch(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	total := ToIntVal(m["total"])
	results, _ := m["results"].([]any)
	b.WriteString("\n" + CountHeader(t, len(results), "results") + "\n\n")

	if len(results) > 0 {
		cols := []Column{
			{Header: "CVE", MinWidth: 16, MaxWidth: 24},
			{Header: "Severity", MinWidth: 8, MaxWidth: 10, Color: func(s string) string { return SeverityText(t, strings.TrimSpace(s)) }},
			{Header: "Score", MinWidth: 5, MaxWidth: 6, Align: AlignRight},
			{Header: "EPSS", MinWidth: 5, MaxWidth: 8, Align: AlignRight},
			{Header: "KEV", MinWidth: 3, MaxWidth: 4},
			{Header: "Stage", MinWidth: 6, MaxWidth: 12},
		}

		rows := make([][]string, 0, len(results))
		for _, r := range results {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			cveID := ToStringVal(rm["cveId"])
			severity := ""
			score := ""
			if metrics, ok := rm["metrics"].(map[string]any); ok {
				severity = ToStringVal(metrics["highestSeverity"])
				if s := ToFloat64(metrics["highestScore"]); s > 0 {
					score = FormatFloat(s, 1)
				}
			}
			epss := ""
			if e := ToFloat64(rm["epss"]); e > 0 {
				epss = FormatFloat(e, 4)
			}
			kev := ""
			if kevData, ok := rm["kev"].(map[string]any); ok {
				if bv, ok := kevData["inCisaKev"].(bool); ok && bv {
					kev = "Yes"
				}
			}
			stage := ""
			if timeline, ok := rm["timeline"].(map[string]any); ok {
				stage = ToStringVal(timeline["lifecycleStage"])
			}
			rows = append(rows, []string{cveID, severity, score, epss, kev, stage})
		}
		b.WriteString(Table(t, cols, rows) + "\n")
	}

	if hasMore, ok := m["hasMore"].(bool); ok && hasMore {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		b.WriteString("\n" + Paginator(t, total, limit, offset, true))
	}

	return b.String()
}

// RenderTimeline renders vulnerability timeline events.
func RenderTimeline(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	if id == "" {
		id = ToStringVal(m["id"])
	}
	b.WriteString("\n" + Bold(t, "Timeline for "+id) + "\n\n")

	events, _ := m["events"].([]any)
	if len(events) == 0 {
		b.WriteString(Muted(t, "  No timeline events") + "\n")
		return b.String()
	}

	dateWidth := 12
	typeWidth := 14
	descWidth := t.Width - dateWidth - typeWidth - 6
	if descWidth < 20 {
		descWidth = 20
	}

	for _, evt := range events {
		if em, ok := evt.(map[string]any); ok {
			evtDate := ""
			if ts, ok := em["date"].(string); ok {
				evtDate = ts
			} else if ts, ok := em["timestamp"].(float64); ok && ts > 0 {
				evtDate = time.Unix(int64(ts), 0).Format("2006-01-02")
			}
			evtType := ToStringVal(em["type"])
			desc := ToStringVal(em["description"])
			if desc == "" {
				desc = ToStringVal(em["title"])
			}

			// Color the event type
			typeStr := PadRight(evtType, typeWidth)
			switch evtType {
			case "exploit":
				typeStr = ErrorStyle(t, typeStr)
			case "patch", "fix":
				typeStr = Success(t, typeStr)
			case "source":
				typeStr = Accent(t, typeStr)
			case "score-change":
				typeStr = Muted(t, typeStr)
			default:
				typeStr = Label(t, typeStr)
			}

			b.WriteString(fmt.Sprintf("  %s  %s  %s\n",
				Muted(t, PadRight(evtDate, dateWidth)),
				typeStr,
				Truncate(desc, descWidth)))
		}
	}

	// Sources section (V2)
	if sources, ok := m["sources"].(map[string]any); ok && len(sources) > 0 {
		b.WriteString("\n" + Subheader(t, "Sources") + "\n")
		for k, v := range sources {
			b.WriteString(fmt.Sprintf("  %s %s\n", Label(t, k+":"), ToStringVal(v)))
		}
	}

	return b.String()
}

// RenderFixes renders fix data for a vulnerability.
func RenderFixes(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	if id == "" {
		id = ToStringVal(m["id"])
	}
	b.WriteString("\n" + Bold(t, "Fixes for "+id) + "\n")

	renderFixSection := func(key, title string) {
		section, ok := m[key]
		if !ok {
			return
		}
		sm, _ := section.(map[string]any)
		if sm == nil {
			return
		}
		if errMsg := ToStringVal(sm["error"]); errMsg != "" {
			b.WriteString("\n" + Subheader(t, title) + "\n")
			b.WriteString("  " + CrossMark(t) + " " + Muted(t, errMsg) + "\n")
			return
		}

		b.WriteString("\n" + Subheader(t, title) + "\n")
		renderMapEntries(t, &b, sm)
	}

	// V2 merged format
	if _, ok := m["registry"]; ok {
		renderFixSection("registry", "Registry Fixes")
		renderFixSection("distributions", "Distribution Patches")
		renderFixSection("source", "Source Fixes")
	} else {
		// V1 format - render as generic key-value
		b.WriteString("\n")
		renderMapEntries(t, &b, m)
	}

	return b.String()
}

// RenderScorecard renders a vulnerability scorecard.
func RenderScorecard(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	if id == "" {
		id = ToStringVal(m["id"])
	}
	repo := ToStringVal(m["repository"])

	header := Bold(t, "Scorecard")
	if id != "" {
		header += " for " + Bold(t, id)
	}
	if repo != "" {
		header += "  " + Muted(t, repo)
	}
	b.WriteString("\n" + header + "\n")

	// Overall score
	if score, ok := m["score"].(float64); ok {
		barWidth := 30
		filled := int(score * float64(barWidth) / 10)
		b.WriteString(fmt.Sprintf("\n  Score: %s  %s\n",
			Bold(t, FormatFloat(score, 1)+"/10"),
			Bar(t, filled, barWidth, barWidth)))
	}

	// Checks
	if checks, ok := m["checks"].([]any); ok && len(checks) > 0 {
		b.WriteString("\n" + Subheader(t, "Checks") + "\n")
		for _, chk := range checks {
			if cm, ok := chk.(map[string]any); ok {
				name := ToStringVal(cm["name"])
				score := ToFloat64(cm["score"])
				mark := CheckMark(t)
				if score < 5 {
					mark = CrossMark(t)
				} else if score < 7 {
					mark = WarningMark(t)
				}
				b.WriteString(fmt.Sprintf("  %s %s %s\n", mark,
					PadRight(name, 30),
					Muted(t, FormatFloat(score, 0)+"/10")))
			}
		}
	}

	return b.String()
}

// RenderRemediationPlan renders a remediation plan.
func RenderRemediationPlan(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])

	// severity can be a string or a nested object
	var baseSeverity string
	var cvssScore, epssScore, epssPercentile, cessScore float64
	var cvssVector, exploitLevel string
	switch sev := m["severity"].(type) {
	case string:
		baseSeverity = sev
	case map[string]any:
		baseSeverity = ToStringVal(sev["baseSeverity"])
		cvssScore = ToFloat64(sev["cvssScore"])
		cvssVector = ToStringVal(sev["cvssVector"])
		epssScore = ToFloat64(sev["epssScore"])
		epssPercentile = ToFloat64(sev["epssPercentile"])
		cessScore = ToFloat64(sev["cessScore"])
		if em, ok := sev["exploitationMaturity"].(map[string]any); ok {
			exploitLevel = ToStringVal(em["level"])
		}
	}

	header := Bold(t, "Remediation Plan for "+id)
	if baseSeverity != "" {
		header += "  " + SeverityBadge(t, strings.ToLower(baseSeverity))
	}
	b.WriteString("\n" + header + "\n")

	// Scores
	barWidth := 20
	if t.Width < 60 {
		barWidth = 12
	}
	hasScores := cvssScore > 0 || epssScore > 0 || cessScore > 0
	if hasScores {
		b.WriteString("\n" + Subheader(t, "Scores") + "\n")
		if cvssScore > 0 {
			scoreLabel := FormatFloat(cvssScore, 1) + "/10"
			styled := scoreLabel
			if baseSeverity != "" && t.HasColor() {
				styled = lipgloss.NewStyle().Foreground(tui.SeverityColor(strings.ToLower(baseSeverity))).Render(scoreLabel)
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s\n",
				Label(t, PadRight("CVSS:", 14)),
				Bar(t, int(cvssScore*10), 100, barWidth), styled))
		}
		if epssScore > 0 {
			pctLabel := FormatFloat(epssScore, 4)
			if epssPercentile > 0 {
				pctLabel += fmt.Sprintf("  (%.1f%% percentile)", epssPercentile*100)
			}
			styledEpss := pctLabel
			if t.HasColor() && epssScore >= 0.7 {
				styledEpss = lipgloss.NewStyle().Foreground(tui.ColorError).Render(pctLabel)
			} else if t.HasColor() && epssScore >= 0.3 {
				styledEpss = lipgloss.NewStyle().Foreground(tui.ColorHigh).Render(pctLabel)
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s\n",
				Label(t, PadRight("EPSS:", 14)),
				Bar(t, int(epssScore*100), 100, barWidth), styledEpss))
		}
		if cessScore > 0 {
			b.WriteString(fmt.Sprintf("  %s %s  %s\n",
				Label(t, PadRight("CESS:", 14)),
				Bar(t, int(cessScore*100), 100, barWidth), FormatFloat(cessScore, 4)))
		}
		if exploitLevel != "" {
			styledExploit := exploitLevel
			if t.HasColor() {
				switch strings.ToUpper(exploitLevel) {
				case "ACTIVE":
					styledExploit = lipgloss.NewStyle().Foreground(tui.ColorCritical).Render(exploitLevel)
				case "HIGH":
					styledExploit = lipgloss.NewStyle().Foreground(tui.ColorHigh).Render(exploitLevel)
				case "POC", "AVAILABLE":
					styledExploit = lipgloss.NewStyle().Foreground(tui.ColorMedium).Render(exploitLevel)
				}
			}
			b.WriteString(fmt.Sprintf("  %s %s\n", Label(t, PadRight("Exploitation:", 14)), styledExploit))
		}
		if cvssVector != "" {
			b.WriteString(fmt.Sprintf("  %s %s\n", Label(t, PadRight("Vector:", 14)), Muted(t, cvssVector)))
		}
	}

	// SSVC (nested object)
	if ssvc, ok := m["ssvc"].(map[string]any); ok {
		decision := ToStringVal(ssvc["decision"])
		priority := ToStringVal(ssvc["priority"])
		if decision != "" {
			b.WriteString("\n" + Subheader(t, "SSVC Assessment") + "\n")
			ssvcStr := decision
			if priority != "" {
				ssvcStr += " (" + priority + ")"
			}
			styledSSVC := ssvcStr
			if t.HasColor() {
				var ssvcColor lipgloss.Color
				switch strings.ToLower(decision) {
				case "act":
					ssvcColor = tui.ColorCritical
				case "attend":
					ssvcColor = tui.ColorHigh
				case "track*":
					ssvcColor = tui.ColorMedium
				default:
					ssvcColor = tui.ColorInfo
				}
				styledSSVC = lipgloss.NewStyle().Foreground(ssvcColor).Render(ssvcStr)
			}
			pairs := []KVPair{{Key: "Decision", Value: styledSSVC}}
			if auto := ToStringVal(ssvc["automatable"]); auto != "" {
				pairs = append(pairs, KVPair{Key: "Automatable", Value: auto})
			}
			if expl := ToStringVal(ssvc["exploitation"]); expl != "" {
				pairs = append(pairs, KVPair{Key: "Exploitation", Value: expl})
			}
			if impact := ToStringVal(ssvc["technicalImpact"]); impact != "" {
				pairs = append(pairs, KVPair{Key: "Technical Impact", Value: impact})
			}
			b.WriteString(KeyValue(t, pairs) + "\n")
		}
	}

	// Fix availability (can be a string or object)
	fixStr := ToStringVal(m["fixAvailability"])
	if fixStr != "" {
		mark := CrossMark(t)
		status := fixStr
		switch strings.ToLower(fixStr) {
		case "no_fix":
			status = "No fix available"
		case "fix_available", "available":
			mark = CheckMark(t)
			status = "Fix available"
		case "partial":
			mark = WarningMark(t)
			status = "Partial fix available"
		}
		b.WriteString("\n  " + mark + " " + Bold(t, status) + "\n")
	}

	// Timeline
	if timeline, ok := m["timeline"].(map[string]any); ok {
		var tlPairs []KVPair
		if pub := ToStringVal(timeline["datePublished"]); pub != "" {
			tlPairs = append(tlPairs, KVPair{Key: "Published", Value: pub})
		}
		if age := ToIntVal(timeline["currentAgeDays"]); age > 0 {
			tlPairs = append(tlPairs, KVPair{Key: "Age", Value: fmt.Sprintf("%d days", age)})
		}
		if stage := ToStringVal(timeline["lifecycleStage"]); stage != "" {
			tlPairs = append(tlPairs, KVPair{Key: "Lifecycle", Value: stage})
		}
		if len(tlPairs) > 0 {
			b.WriteString("\n" + KeyValue(t, tlPairs) + "\n")
		}
	}

	// Actions
	if actions, ok := m["actions"].([]any); ok && len(actions) > 0 {
		b.WriteString("\n" + Subheader(t, "Actions") + "\n")
		for i, act := range actions {
			am, ok := act.(map[string]any)
			if !ok {
				continue
			}
			title := ToStringVal(am["title"])
			desc := ToStringVal(am["description"])
			effort := ToStringVal(am["effort"])
			actType := ToStringVal(am["type"])

			prefix := fmt.Sprintf("  %d.", i+1)
			titleLine := Bold(t, title)
			tags := []string{}
			if actType != "" {
				tags = append(tags, actType)
			}
			if effort != "" {
				tags = append(tags, "effort: "+effort)
			}
			if len(tags) > 0 {
				titleLine += "  " + Muted(t, "["+strings.Join(tags, ", ")+"]")
			}
			b.WriteString(fmt.Sprintf("%s %s\n", prefix, titleLine))
			if desc != "" {
				b.WriteString("     " + wordWrap(desc, t.Width-6) + "\n")
			}

			// Steps
			if steps, ok := am["steps"].([]any); ok && len(steps) > 0 {
				for _, step := range steps {
					b.WriteString("     • " + ToStringVal(step) + "\n")
				}
			}
		}
	}

	// CWEs (deduplicated by ID, prefer entry with name)
	if cwes, ok := m["cwes"].([]any); ok && len(cwes) > 0 {
		b.WriteString("\n" + Subheader(t, "CWEs") + "\n")
		seen := make(map[string]string) // cweID → display string
		var order []string
		for _, c := range cwes {
			var cweID, entry string
			if cm, ok := c.(map[string]any); ok {
				cweID = ToStringVal(cm["cweId"])
				name := ToStringVal(cm["name"])
				if name != "" && name != cweID && !strings.HasPrefix(name, cweID+":") {
					entry = cweID + " — " + name
				} else if name != "" && strings.HasPrefix(name, cweID+":") {
					entry = name
				} else {
					entry = cweID
				}
			} else {
				cweID = ToStringVal(c)
				entry = cweID
			}
			if cweID == "" {
				continue
			}
			if existing, ok := seen[cweID]; !ok {
				seen[cweID] = entry
				order = append(order, cweID)
			} else if len(entry) > len(existing) {
				seen[cweID] = entry // prefer longer (has name)
			}
		}
		items := make([]string, 0, len(order))
		for _, id := range order {
			items = append(items, seen[id])
		}
		b.WriteString(BulletList(t, items) + "\n")
	}

	// Guidance (string or map)
	guidanceStr := ToStringVal(m["guidance"])
	if guidanceStr != "" {
		b.WriteString("\n" + Subheader(t, "Guidance") + "\n")
		b.WriteString("  " + wordWrap(guidanceStr, t.Width-4) + "\n")
	} else if guidance, ok := m["guidance"].(map[string]any); ok && len(guidance) > 0 {
		b.WriteString("\n" + Subheader(t, "CWE Guidance") + "\n")
		for k, v := range guidance {
			b.WriteString(fmt.Sprintf("  %s\n  %s\n\n", Bold(t, k), wordWrap(ToStringVal(v), t.Width-4)))
		}
	}

	return b.String()
}

// RenderCloudLocators renders cloud resource locator templates.
func RenderCloudLocators(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	b.WriteString("\n" + Bold(t, "Cloud Resource Locators") + "\n")

	if locators, ok := m["locators"].([]any); ok && len(locators) > 0 {
		for _, loc := range locators {
			if lm, ok := loc.(map[string]any); ok {
				provider := ToStringVal(lm["provider"])
				template := ToStringVal(lm["template"])
				b.WriteString(fmt.Sprintf("\n  %s\n", Subheader(t, provider)))
				b.WriteString(fmt.Sprintf("  %s\n", Accent(t, template)))
			}
		}
	} else {
		// Render as grouped map
		renderMapEntries(t, &b, m)
	}

	return b.String()
}

// RenderAdvisories renders advisory data.
func RenderAdvisories(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	b.WriteString("\n" + Bold(t, "Advisories for "+id) + "\n")

	if advisories, ok := m["advisories"].([]any); ok && len(advisories) > 0 {
		b.WriteString(Muted(t, fmt.Sprintf("  %d advisory/advisories found", len(advisories))) + "\n\n")
		for i, adv := range advisories {
			if am, ok := adv.(map[string]any); ok {
				source := ToStringVal(am["source"])
				advID := ToStringVal(am["id"])
				if advID == "" {
					advID = ToStringVal(am["advisoryId"])
				}
				title := ToStringVal(am["title"])
				url := ToStringVal(am["url"])

				prefix := fmt.Sprintf("  %d.", i+1)
				name := advID
				if name == "" {
					name = title
				}
				b.WriteString(fmt.Sprintf("%s %s", prefix, Bold(t, name)))
				if source != "" {
					b.WriteString("  " + Muted(t, "["+source+"]"))
				}
				b.WriteString("\n")
				if title != "" && title != name {
					b.WriteString("     " + title + "\n")
				}
				if url != "" {
					b.WriteString("     " + Muted(t, Truncate(url, t.Width-6)) + "\n")
				}
			}
		}
	} else {
		b.WriteString(Muted(t, "  No advisories found") + "\n")
	}

	return b.String()
}

// RenderWorkarounds renders workaround information.
func RenderWorkarounds(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	b.WriteString("\n" + Bold(t, "Workarounds for "+id) + "\n")

	if workarounds, ok := m["workarounds"].([]any); ok && len(workarounds) > 0 {
		for i, wa := range workarounds {
			if wm, ok := wa.(map[string]any); ok {
				desc := ToStringVal(wm["description"])
				source := ToStringVal(wm["source"])
				prefix := fmt.Sprintf("\n  %d.", i+1)
				b.WriteString(prefix)
				if source != "" {
					b.WriteString(" " + Muted(t, "["+source+"]"))
				}
				b.WriteString("\n")
				if desc != "" {
					b.WriteString("     " + wordWrap(desc, t.Width-6) + "\n")
				}
			}
		}
	} else {
		b.WriteString(Muted(t, "  No workarounds found") + "\n")
	}

	return b.String()
}

// RenderKev renders CISA KEV data.
func RenderKev(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	b.WriteString("\n" + Bold(t, "CISA KEV Status for "+id) + "\n\n")

	if kev, ok := m["kev"].(map[string]any); ok {
		pairs := []KVPair{}
		if v := ToStringVal(kev["dateAdded"]); v != "" {
			pairs = append(pairs, KVPair{Key: "Date Added", Value: v})
		}
		if v := ToStringVal(kev["dueDate"]); v != "" {
			pairs = append(pairs, KVPair{Key: "Due Date", Value: v, ValueStyle: func(s string) string { return ErrorStyle(t, s) }})
		}
		if v := ToStringVal(kev["vendorProject"]); v != "" {
			pairs = append(pairs, KVPair{Key: "Vendor/Project", Value: v})
		}
		if v := ToStringVal(kev["product"]); v != "" {
			pairs = append(pairs, KVPair{Key: "Product", Value: v})
		}
		if v := ToStringVal(kev["vulnerabilityName"]); v != "" {
			pairs = append(pairs, KVPair{Key: "Name", Value: v})
		}
		if v := ToStringVal(kev["shortDescription"]); v != "" {
			pairs = append(pairs, KVPair{Key: "Description", Value: wordWrap(v, t.Width-25)})
		}
		if v := ToStringVal(kev["requiredAction"]); v != "" {
			pairs = append(pairs, KVPair{Key: "Required Action", Value: wordWrap(v, t.Width-25)})
		}
		if len(pairs) > 0 {
			b.WriteString(KeyValue(t, pairs))
		} else {
			renderMapEntries(t, &b, kev)
		}
	} else {
		// Might be directly in the top-level map
		inKev := false
		if bv, ok := m["inKev"].(bool); ok {
			inKev = bv
		}
		if inKev {
			b.WriteString("  " + CheckMark(t) + " " + Bold(t, "In CISA KEV") + "\n")
			renderMapEntries(t, &b, m)
		} else {
			b.WriteString("  " + Muted(t, "Not in CISA KEV") + "\n")
		}
	}

	return b.String()
}

// RenderCweGuidance renders CWE-based guidance.
func RenderCweGuidance(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	b.WriteString("\n" + Bold(t, "CWE Guidance for "+id) + "\n")

	if guidance, ok := m["guidance"].([]any); ok && len(guidance) > 0 {
		for _, g := range guidance {
			if gm, ok := g.(map[string]any); ok {
				cweID := ToStringVal(gm["cweId"])
				name := ToStringVal(gm["name"])
				desc := ToStringVal(gm["description"])
				mitigation := ToStringVal(gm["mitigation"])

				b.WriteString(fmt.Sprintf("\n  %s", Bold(t, cweID)))
				if name != "" {
					b.WriteString(" — " + name)
				}
				b.WriteString("\n")
				if desc != "" {
					b.WriteString("  " + wordWrap(desc, t.Width-4) + "\n")
				}
				if mitigation != "" {
					b.WriteString("\n  " + Subheader(t, "Mitigation") + "\n")
					b.WriteString("  " + wordWrap(mitigation, t.Width-4) + "\n")
				}
			}
		}
	} else {
		// Might be a single guidance object
		renderMapEntries(t, &b, m)
	}

	return b.String()
}

// RenderAffected renders affected products/packages.
func RenderAffected(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	b.WriteString("\n" + Bold(t, "Affected Products for "+id) + "\n")

	if affected, ok := m["affected"].([]any); ok && len(affected) > 0 {
		b.WriteString(Muted(t, fmt.Sprintf("  %d affected entries", len(affected))) + "\n\n")

		cols := []Column{
			{Header: "Package", MinWidth: 15, MaxWidth: 30},
			{Header: "Ecosystem", MinWidth: 8, MaxWidth: 15},
			{Header: "Versions", MinWidth: 10, MaxWidth: 30},
		}

		rows := make([][]string, 0, len(affected))
		for _, a := range affected {
			if am, ok := a.(map[string]any); ok {
				pkg := ToStringVal(am["packageName"])
				if pkg == "" {
					pkg = ToStringVal(am["product"])
				}
				eco := ToStringVal(am["ecosystem"])
				ver := ToStringVal(am["versionRange"])
				if ver == "" {
					ver = ToStringVal(am["versions"])
				}
				rows = append(rows, []string{pkg, eco, ver})
			}
		}
		b.WriteString(Table(t, cols, rows) + "\n")
	} else {
		renderMapEntries(t, &b, m)
	}

	if total := ToIntVal(m["total"]); total > 0 {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		hasMore, _ := m["hasMore"].(bool)
		if hasMore {
			b.WriteString("\n" + Paginator(t, total, limit, offset, true))
		}
	}

	return b.String()
}

// RenderScorecardSearch renders scorecard search results.
func RenderScorecardSearch(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	b.WriteString("\n" + Bold(t, "Scorecard Search Results") + "\n\n")

	if results, ok := m["results"].([]any); ok && len(results) > 0 {
		cols := []Column{
			{Header: "Repository", MinWidth: 20, MaxWidth: 50},
			{Header: "Score", MinWidth: 5, MaxWidth: 8, Align: AlignRight},
		}

		rows := make([][]string, 0, len(results))
		for _, r := range results {
			if rm, ok := r.(map[string]any); ok {
				repo := ToStringVal(rm["repository"])
				score := FormatFloat(ToFloat64(rm["score"]), 1)
				rows = append(rows, []string{repo, score})
			}
		}
		b.WriteString(Table(t, cols, rows) + "\n")
	} else {
		b.WriteString(Muted(t, "  No results found") + "\n")
	}

	return b.String()
}

// RenderGenericMap renders any map data with intelligent formatting.
// Used as fallback for commands without specific renderers.
func RenderGenericMap(data any, ctx *Context) string {
	t := ctx.Term
	var b strings.Builder

	switch d := data.(type) {
	case map[string]any:
		b.WriteString("\n")
		renderMapEntries(t, &b, d)
	case []any:
		b.WriteString("\n")
		for i, item := range d {
			if i > 0 {
				b.WriteString("\n")
			}
			if im, ok := item.(map[string]any); ok {
				renderMapEntries(t, &b, im)
			} else {
				b.WriteString(fmt.Sprintf("  %v\n", item))
			}
		}
	default:
		b.WriteString(fmt.Sprintf("%v", data))
	}

	return b.String()
}

// RenderSimpleList renders a generic list of items from a map response.
// Looks for common patterns: items[], results[], data[], or the top-level array.
// RenderSimpleList renders a generic list with name/count from common list keys.
func RenderSimpleList(data any, ctx *Context, noun string) string {
	t := ctx.Term
	var b strings.Builder

	m, ok := data.(map[string]any)
	if !ok {
		return RenderGenericMap(data, ctx)
	}

	// Find the main list key
	var items []any
	for _, key := range []string{"items", "results", "data", "types", "sources",
		"distributions", "metricTypes", "exploitSources", "exploitTypes", "packages"} {
		if arr, ok := m[key].([]any); ok {
			items = arr
			break
		}
	}

	total := len(items)
	if tv := ToIntVal(m["total"]); tv > 0 {
		total = tv
	}

	b.WriteString("\n" + CountHeader(t, total, noun) + "\n\n")

	if len(items) > 0 {
		// Determine if items have counts → use table
		hasCount := false
		for _, item := range items {
			if im, ok := item.(map[string]any); ok {
				if ToIntVal(im["count"]) > 0 {
					hasCount = true
					break
				}
			}
		}

		if hasCount {
			cols := []Column{
				{Header: "Name", MinWidth: 15, MaxWidth: 35},
				{Header: "Count", MinWidth: 8, MaxWidth: 14, Align: AlignRight},
			}
			// Check for extra columns
			hasDisplay := false
			hasPrefix := false
			for _, item := range items[:1] {
				if im, ok := item.(map[string]any); ok {
					if ToStringVal(im["displayName"]) != "" {
						hasDisplay = true
					}
					if ToStringVal(im["advisoryPrefix"]) != "" {
						hasPrefix = true
					}
				}
			}
			if hasDisplay {
				cols = []Column{
					{Header: "Name", MinWidth: 10, MaxWidth: 20},
					{Header: "Display Name", MinWidth: 10, MaxWidth: 25},
					{Header: "Count", MinWidth: 8, MaxWidth: 14, Align: AlignRight},
				}
			}
			if hasPrefix {
				cols = []Column{
					{Header: "Name", MinWidth: 10, MaxWidth: 20},
					{Header: "Display Name", MinWidth: 10, MaxWidth: 20},
					{Header: "Prefix", MinWidth: 4, MaxWidth: 8},
					{Header: "Count", MinWidth: 8, MaxWidth: 14, Align: AlignRight},
				}
			}

			rows := make([][]string, 0, len(items))
			for _, item := range items {
				if im, ok := item.(map[string]any); ok {
					name := ToStringVal(im["name"])
					if name == "" {
						name = ToStringVal(im["id"])
					}
					count := FormatNumber(ToIntVal(im["count"]))
					if hasPrefix {
						rows = append(rows, []string{
							name,
							ToStringVal(im["displayName"]),
							ToStringVal(im["advisoryPrefix"]),
							count,
						})
					} else if hasDisplay {
						rows = append(rows, []string{name, ToStringVal(im["displayName"]), count})
					} else {
						rows = append(rows, []string{name, count})
					}
				}
			}
			b.WriteString(Table(t, cols, rows) + "\n")
		} else {
			strs := make([]string, 0, len(items))
			for _, item := range items {
				switch v := item.(type) {
				case string:
					strs = append(strs, v)
				case map[string]any:
					name := ToStringVal(v["name"])
					if name == "" {
						name = ToStringVal(v["id"])
					}
					if name == "" {
						name = ToStringVal(v["type"])
					}
					desc := ToStringVal(v["description"])
					if desc != "" {
						name += "  " + Muted(t, desc)
					}
					strs = append(strs, name)
				default:
					strs = append(strs, fmt.Sprintf("%v", item))
				}
			}
			b.WriteString(BulletList(t, strs) + "\n")
		}
	}

	// Pagination
	if hasMore, ok := m["hasMore"].(bool); ok && hasMore {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		b.WriteString("\n" + Paginator(t, total, limit, offset, true))
	}

	return b.String()
}

// RenderPackagesSearch renders package search results with vuln/version counts.
func RenderPackagesSearch(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return RenderGenericMap(data, ctx)
	}
	t := ctx.Term
	var b strings.Builder

	packages, _ := m["packages"].([]any)
	total := len(packages)
	if tv := ToIntVal(m["total"]); tv > 0 {
		total = tv
	}

	b.WriteString("\n" + CountHeader(t, total, "packages") + "\n\n")

	if len(packages) > 0 {
		cols := []Column{
			{Header: "Package", MinWidth: 20, MaxWidth: 40},
			{Header: "Ecosystem", MinWidth: 5, MaxWidth: 12},
			{Header: "Vulns", MinWidth: 5, MaxWidth: 6, Align: AlignRight,
				Color: func(s string) string {
					if strings.TrimSpace(s) != "0" && strings.TrimSpace(s) != "" {
						return ErrorStyle(t, s)
					}
					return s
				}},
			{Header: "Versions", MinWidth: 5, MaxWidth: 8, Align: AlignRight},
			{Header: "Vendor", MinWidth: 8, MaxWidth: 18},
		}

		rows := make([][]string, 0, len(packages))
		for _, pkg := range packages {
			pm, ok := pkg.(map[string]any)
			if !ok {
				continue
			}
			name := ToStringVal(pm["packageName"])
			eco := ""
			if ecos, ok := pm["ecosystems"].([]any); ok && len(ecos) > 0 {
				eco = ToStringVal(ecos[0])
			}
			vulns := FormatNumber(ToIntVal(pm["vulnCount"]))
			versions := FormatNumber(ToIntVal(pm["versionCount"]))
			vendor := ToStringVal(pm["vendor"])
			rows = append(rows, []string{name, eco, vulns, versions, vendor})
		}
		b.WriteString(Table(t, cols, rows) + "\n")
	}

	if hasMore, _ := m["hasMore"].(bool); hasMore {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		b.WriteString("\n" + Paginator(t, total, limit, offset, true))
	}

	return b.String()
}

// RenderVersions renders package version list.
func RenderVersions(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return RenderGenericMap(data, ctx)
	}
	t := ctx.Term
	var b strings.Builder

	pkgName := ToStringVal(m["packageName"])
	total := ToIntVal(m["total"])
	versions, _ := m["versions"].([]any)

	b.WriteString("\n" + Bold(t, fmt.Sprintf("Versions for %s", pkgName)))
	b.WriteString("  " + Muted(t, fmt.Sprintf("%s total", FormatNumber(total))) + "\n\n")

	if len(versions) > 0 {
		cols := []Column{
			{Header: "Version", MinWidth: 10, MaxWidth: 30},
			{Header: "Ecosystem", MinWidth: 5, MaxWidth: 15},
			{Header: "Sources", MinWidth: 8, MaxWidth: 30},
		}
		rows := make([][]string, 0, len(versions))
		for _, v := range versions {
			vm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			ver := ToStringVal(vm["version"])
			eco := ToStringVal(vm["ecosystem"])
			srcList := ""
			if sources, ok := vm["sources"].([]any); ok {
				strs := make([]string, 0, len(sources))
				for _, s := range sources {
					strs = append(strs, ToStringVal(s))
				}
				srcList = strings.Join(strs, ", ")
			}
			rows = append(rows, []string{ver, eco, srcList})
		}
		b.WriteString(Table(t, cols, rows) + "\n")
	}

	if hasMore, _ := m["hasMore"].(bool); hasMore {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		b.WriteString("\n" + Paginator(t, total, limit, offset, true))
	}

	return b.String()
}

// RenderProductVersions renders product version list.
func RenderProductVersions(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return RenderGenericMap(data, ctx)
	}
	t := ctx.Term
	var b strings.Builder

	total := ToIntVal(m["total"])
	pkgName := ToStringVal(m["packageName"])

	b.WriteString("\n" + Bold(t, fmt.Sprintf("Versions for %s", pkgName)) + "\n")
	b.WriteString(Muted(t, fmt.Sprintf("  %s total versions", FormatNumber(total))) + "\n\n")

	if versions, ok := m["versions"].([]any); ok && len(versions) > 0 {
		for i, v := range versions {
			if vm, ok := v.(map[string]any); ok {
				ver := ToStringVal(vm["version"])
				eco := ToStringVal(vm["ecosystem"])
				line := fmt.Sprintf("%s %s", Bold(t, ver), Muted(t, "("+eco+")"))

				b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, line))

				// CVE IDs
				if cves, ok := vm["cveIds"].([]any); ok && len(cves) > 0 {
					ids := make([]string, 0, len(cves))
					for _, c := range cves {
						ids = append(ids, ToStringVal(c))
					}
					b.WriteString("     " + Label(t, "CVEs:") + " " + strings.Join(ids, ", ") + "\n")
				}

				// Sources
				if sources, ok := vm["sources"].([]any); ok && len(sources) > 0 {
					tableCounts := make(map[string]int)
					for _, s := range sources {
						if sm, ok := s.(map[string]any); ok {
							tableCounts[ToStringVal(sm["sourceTable"])]++
						}
					}
					var tables []string
					for table, count := range tableCounts {
						tables = append(tables, fmt.Sprintf("%s(%d)", table, count))
					}
					sort.Strings(tables)
					b.WriteString("     " + Label(t, "Sources:") + " " + strings.Join(tables, ", ") + "\n")
				}
			}
		}
	}

	if hasMore, _ := m["hasMore"].(bool); hasMore {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		b.WriteString("\n" + Paginator(t, total, limit, offset, true))
	}

	return b.String()
}

// RenderPackageVulns renders package vulnerability list.
func RenderPackageVulns(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return RenderGenericMap(data, ctx)
	}
	t := ctx.Term
	var b strings.Builder

	totalCVEs := ToIntVal(m["totalCVEs"])
	total := ToIntVal(m["total"])

	var items []any
	if v, ok := m["versions"].([]any); ok && len(v) > 0 {
		items = v
	} else if v, ok := m["vulnerabilities"].([]any); ok && len(v) > 0 {
		items = v
	}

	b.WriteString("\n" + Bold(t, fmt.Sprintf("Found %s CVE(s) across %d version(s)",
		FormatNumber(totalCVEs), len(items))) + "\n\n")

	for i, item := range items {
		if vm, ok := item.(map[string]any); ok {
			ver := ToStringVal(vm["version"])
			eco := ToStringVal(vm["ecosystem"])
			sources, _ := vm["sources"].([]any)

			b.WriteString(fmt.Sprintf("  %d. %s %s — %d source(s)\n",
				i+1, Bold(t, ver), Muted(t, "("+eco+")"), len(sources)))

			for _, src := range sources {
				if sm, ok := src.(map[string]any); ok {
					table := ToStringVal(sm["sourceTable"])
					srcID := ToStringVal(sm["sourceId"])
					if srcID == "" {
						srcID = ToStringVal(sm["sourceID"])
					}
					b.WriteString(fmt.Sprintf("     • %s: %s\n", Accent(t, table), srcID))
				}
			}
		}
	}

	if hasMore, _ := m["hasMore"].(bool); hasMore {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		b.WriteString("\n" + Paginator(t, total, limit, offset, true))
	}

	return b.String()
}

// RenderIdentifiers renders a list of CVE identifiers.
func RenderIdentifiers(data any, ctx *Context, title string) string {
	m, ok := data.(map[string]any)
	if !ok {
		return RenderGenericMap(data, ctx)
	}
	t := ctx.Term
	var b strings.Builder

	total := ToIntVal(m["total"])
	b.WriteString("\n" + CountHeader(t, total, title) + "\n\n")

	if ids, ok := m["identifiers"].([]any); ok && len(ids) > 0 {
		items := make([]string, 0, len(ids))
		for _, id := range ids {
			switch v := id.(type) {
			case string:
				items = append(items, v)
			case map[string]any:
				gcveID := ToStringVal(v["gcveId"])
				cveID := ToStringVal(v["cveId"])
				if gcveID != "" {
					items = append(items, fmt.Sprintf("%s  %s", gcveID, Muted(t, cveID)))
				} else if cveID != "" {
					items = append(items, cveID)
				} else {
					items = append(items, fmt.Sprintf("%v", v))
				}
			}
		}
		b.WriteString(BulletList(t, items) + "\n")
	}

	if hasMore, _ := m["hasMore"].(bool); hasMore {
		offset := ToIntVal(m["offset"])
		limit := ToIntVal(m["limit"])
		b.WriteString("\n" + Paginator(t, total, limit, offset, true))
	}

	return b.String()
}

// --- helpers ---

// renderMapEntries renders map entries as key-value pairs.
func renderMapEntries(t *Terminal, b *strings.Builder, m map[string]any) {
	// Sort keys for consistent output
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := m[k]
		switch val := v.(type) {
		case map[string]any:
			b.WriteString("  " + Subheader(t, k) + "\n")
			renderMapEntries(t, b, val)
		case []any:
			b.WriteString("  " + Label(t, k+":") + " ")
			if len(val) == 0 {
				b.WriteString(Muted(t, "(empty)") + "\n")
			} else if _, isStr := val[0].(string); isStr {
				strs := make([]string, len(val))
				for i, s := range val {
					strs[i] = ToStringVal(s)
				}
				b.WriteString(strings.Join(strs, ", ") + "\n")
			} else {
				b.WriteString(fmt.Sprintf("%d items\n", len(val)))
				for _, item := range val {
					if im, ok := item.(map[string]any); ok {
						renderMapEntries(t, b, im)
					} else {
						b.WriteString(fmt.Sprintf("    %v\n", item))
					}
				}
			}
		case nil:
			// skip
		default:
			b.WriteString(fmt.Sprintf("  %s %v\n", Label(t, k+":"), v))
		}
	}
}

// wordWrap wraps text at word boundaries to fit within maxWidth.
func wordWrap(s string, maxWidth int) string {
	if maxWidth <= 0 || len(s) <= maxWidth {
		return s
	}

	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}

	var lines []string
	currentLine := words[0]

	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= maxWidth {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)

	return strings.Join(lines, "\n")
}
