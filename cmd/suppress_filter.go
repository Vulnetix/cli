package cmd

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/suppress"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// vdbSuppressGetReq builds a repo-scoped, active-only suppression fetch request.
func vdbSuppressGetReq(git *gitctx.GitContext) vdb.CliSuppressionsGetRequest {
	req := vdb.CliSuppressionsGetRequest{ActiveOnly: true}
	if git != nil {
		req.RepositoryFullName = suppress.RepoFullName(git.RemoteURLs)
		req.BranchName = git.CurrentBranch
	}
	return req
}

// kindToCategory maps a rego rule's metadata Kind to the Suppression category
// vocabulary shared with the backend / website.
func kindToCategory(kind string) string {
	switch kind {
	case "oci", "container":
		return "container"
	default:
		return kind // sast | secrets | iac
	}
}

// buildScanSuppressionSet loads the active suppression rules from local memory
// and (best-effort) the backend, scoped to the scanned repo, into one matcher.
// A nil/blank result means "nothing to filter".
func buildScanSuppressionSet(mem *memory.Memory, git *gitctx.GitContext) *suppress.Set {
	now := time.Now().Unix()
	var rules []suppress.Rule
	if mem != nil {
		rules = append(rules, suppress.FromMemory(mem.ActiveSuppressions(now))...)
	}

	if client := newCliClient(); client != nil {
		req := vdbSuppressGetReq(git)
		if resp, err := client.CliSuppressionsGet(envForCliWithGit(git), req); err == nil && resp != nil {
			for _, s := range resp.Data.Suppressions {
				rules = append(rules, suppress.Rule{
					UUID:               s.UUID,
					RuleID:             s.RuleID,
					Category:           s.Category,
					Type:               s.SuppressionType,
					Reason:             s.Reason,
					TargetValue:        s.TargetValue,
					FilePath:           s.FilePath,
					LineNumber:         s.LineNumber,
					LineRange:          s.LineRange,
					RepositoryFullName: s.RepositoryFullName,
					Branch:             s.BranchName,
					ExpiresAt:          s.ExpiresAt,
					IsActive:           s.IsActive,
				})
			}
		}
	}

	return suppress.NewSet(rules, now)
}

// scanSuppressionSetLoad loads local memory + remote rules into a matcher,
// loading memory.yaml itself (for choke points that run before the shared mem
// is loaded, e.g. the SCA path).
func scanSuppressionSetLoad(rootPath string, git *gitctx.GitContext) *suppress.Set {
	mem, _ := memory.Load(filepath.Join(rootPath, ".vulnetix"))
	return buildScanSuppressionSet(mem, git)
}

// filterSuppressedVulns drops SCA vulns covered by an active suppression rule
// (matched by CVE/vuln id or manifest source file).
func filterSuppressedVulns(vulns []scan.EnrichedVuln, set *suppress.Set) ([]scan.EnrichedVuln, int) {
	if set == nil || set.Empty() || len(vulns) == 0 {
		return vulns, 0
	}
	kept := vulns[:0]
	dropped := 0
	for _, v := range vulns {
		if set.Suppresses(suppress.Finding{Category: "sca", FindingID: v.CveID, FilePath: v.SourceFile}) {
			dropped++
			continue
		}
		kept = append(kept, v)
	}
	return kept, dropped
}

// filterSuppressedLicenseFindings drops license-policy findings covered by an
// active suppression rule (matched by rule id, SPDX id or source file).
func filterSuppressedLicenseFindings(findings []license.Finding, set *suppress.Set) ([]license.Finding, int) {
	if set == nil || set.Empty() || len(findings) == 0 {
		return findings, 0
	}
	kept := findings[:0]
	dropped := 0
	for _, f := range findings {
		m := suppress.Finding{
			Category:  "license",
			RuleID:    f.ID,
			FindingID: f.Package.LicenseSpdxID,
			FilePath:  f.Package.SourceFile,
		}
		if set.Suppresses(m) {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	return kept, dropped
}

// filterSuppressedMalscanFindings drops malware-scan findings covered by an
// active suppression rule (matched by rule id or file path).
func filterSuppressedMalscanFindings(findings []malscanFinding, set *suppress.Set) ([]malscanFinding, int) {
	if set == nil || set.Empty() || len(findings) == 0 {
		return findings, 0
	}
	kept := findings[:0]
	dropped := 0
	for _, f := range findings {
		if set.Suppresses(suppress.Finding{Category: "malware", RuleID: f.RuleID, FilePath: f.File}) {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	return kept, dropped
}

// filterSuppressedFindings drops rego-engine findings covered by an active
// suppression rule and returns the kept slice plus the drop count.
func filterSuppressedFindings(findings []sast.Finding, set *suppress.Set) ([]sast.Finding, int) {
	if set == nil || set.Empty() || len(findings) == 0 {
		return findings, 0
	}
	kept := findings[:0]
	dropped := 0
	for _, f := range findings {
		kind := ""
		if f.Metadata != nil {
			kind = f.Metadata.Kind
		}
		match := suppress.Finding{
			Category: kindToCategory(kind),
			RuleID:   f.RuleID,
			FilePath: f.ArtifactURI,
		}
		if set.Suppresses(match) {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	return kept, dropped
}

// ─── Inventory (CBOM / AIBOM) ─────────────────────────────────────────────
//
// Inventory components are not findings: they carry no rego rule id and no CVE,
// so they are anchored by value (an algorithm SPDX id, a certificate subject, a
// purl, a model name) and by where they were observed. A component's location
// lives on its evidence, whose Locator is "path:line" (internal/cbom.locOf and
// the AIBOM detect passes), so a file/line anchor is tested against every
// evidence site rather than against one canonical path.

// evidenceSite is one place a component was observed.
type evidenceSite struct {
	path string
	line int
}

// evidenceSites splits a component's evidence locators into path/line pairs.
// A locator with no ":line" suffix yields line 0, which makes any line range on
// the rule non-binding for that site rather than silently excluding it.
func evidenceSites(ev []cyclonedx.AIEvidence) []evidenceSite {
	out := make([]evidenceSite, 0, len(ev))
	for _, e := range ev {
		site := evidenceSite{path: e.Locator}
		if i := strings.LastIndex(site.path, ":"); i > 0 {
			if n, err := strconv.Atoi(site.path[i+1:]); err == nil {
				site.line = n
				site.path = site.path[:i]
			}
		}
		out = append(out, site)
	}
	return out
}

// componentSuppressed reports whether an inventory component is covered by an
// active rule. Each of the component's identities is tried in turn, because a
// user may have written the rule against whichever one the console showed them
// (SPDX id, display name, purl). A rule with no file anchor matches wherever the
// component was seen; a rule with one must match an evidence site.
func componentSuppressed(set *suppress.Set, category string, values []string, ev []cyclonedx.AIEvidence) bool {
	_, dropped := componentSuppression(set, category, values, ev)
	return dropped
}

// componentSuppression decides what survives for one component.
//
// The distinction matters because a CBOM/AIBOM component is one entry with many
// evidence sites. A rule with no file anchor ("ignore MD5 everywhere") covers
// the component outright. A file- or line-anchored rule ("ignore MD5 in
// test/fixtures.go") covers only the sites it matches — the component survives
// carrying the rest, and disappears only once every site is covered. Dropping
// the whole component on the first matching site would make the console's
// "This occurrence only" scope quietly hide occurrences elsewhere, which for a
// security inventory is the dangerous direction to be wrong in.
func componentSuppression(set *suppress.Set, category string, values []string, ev []cyclonedx.AIEvidence) (kept []cyclonedx.AIEvidence, dropped bool) {
	if set == nil || set.Empty() {
		return ev, false
	}

	nonEmpty := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			nonEmpty = append(nonEmpty, v)
		}
	}
	if len(nonEmpty) == 0 {
		return ev, false
	}

	// A component with no evidence can only be matched by its value.
	if len(ev) == 0 {
		for _, v := range nonEmpty {
			if set.Suppresses(suppress.Finding{Category: category, Value: v}) {
				return nil, true
			}
		}
		return ev, false
	}

	sites := evidenceSites(ev)
	keptEv := make([]cyclonedx.AIEvidence, 0, len(ev))
	for i, s := range sites {
		covered := false
		for _, v := range nonEmpty {
			r, ok := set.Match(suppress.Finding{Category: category, Value: v, FilePath: s.path, Line: s.line})
			if !ok {
				continue
			}
			// An unanchored rule covers the component wherever it appears; there
			// is nothing left to keep.
			if r.FilePath == "" {
				return nil, true
			}
			covered = true
			break
		}
		if !covered {
			keptEv = append(keptEv, ev[i])
		}
	}
	if len(keptEv) == 0 {
		return nil, true
	}
	return keptEv, false
}

// filterSuppressedCryptoDetections drops CBOM algorithms, certificates and
// libraries covered by an active suppression rule. The caller must recompute
// det.Summary afterwards so the posture rollup and --fail-on agree with what
// was kept.
func filterSuppressedCryptoDetections(det *cyclonedx.CryptoDetections, set *suppress.Set) int {
	if det == nil || set == nil || set.Empty() {
		return 0
	}
	dropped := 0

	assets := det.Assets[:0]
	for _, a := range det.Assets {
		kept, drop := componentSuppression(set, "crypto", []string{a.SPDXID, a.Name, a.OID}, a.Evidence)
		if drop {
			dropped++
			continue
		}
		a.Occurrences, a.Evidence = adjustOccurrences(a.Occurrences, a.Evidence, kept), kept
		assets = append(assets, a)
	}
	det.Assets = assets

	certs := det.Certificates[:0]
	for _, c := range det.Certificates {
		kept, drop := componentSuppression(set, "crypto", []string{c.Name, c.Subject, c.SignatureAlgorithm}, c.Evidence)
		if drop {
			dropped++
			continue
		}
		c.Evidence = kept
		certs = append(certs, c)
	}
	det.Certificates = certs

	libs := det.Libraries[:0]
	for _, l := range det.Libraries {
		kept, drop := componentSuppression(set, "crypto", []string{l.ID, l.Name, l.Purl}, l.Evidence)
		if drop {
			dropped++
			continue
		}
		l.Evidence = kept
		libs = append(libs, l)
	}
	det.Libraries = libs

	return dropped
}

// adjustOccurrences keeps a component's occurrence count in step with the
// evidence that survived. The detectors increment the two together, so leaving
// the count alone after filtering would report uses the report no longer shows.
func adjustOccurrences(occurrences int, before, after []cyclonedx.AIEvidence) int {
	if occurrences <= 0 || len(before) == len(after) {
		return occurrences
	}
	n := occurrences - (len(before) - len(after))
	if n < len(after) {
		n = len(after)
	}
	if n < 0 {
		return 0
	}
	return n
}

// filterSuppressedAIDetections drops AIBOM tools, SDKs, models, infrastructure
// and data artifacts covered by an active suppression rule. An ignored AI
// component is skipped entirely — it never reaches memory.yaml, the emitted
// CycloneDX or the backend — which is what makes it invisible in the console.
func filterSuppressedAIDetections(det *cyclonedx.AIDetections, set *suppress.Set) int {
	if det == nil || set == nil || set.Empty() {
		return 0
	}
	dropped := 0

	tools := det.Tools[:0]
	for _, t := range det.Tools {
		kept, drop := componentSuppression(set, "ai", []string{t.ID, t.Name}, t.Evidence)
		if drop {
			dropped++
			continue
		}
		t.Evidence = kept
		tools = append(tools, t)
	}
	det.Tools = tools

	libs := det.Libraries[:0]
	for _, l := range det.Libraries {
		kept, drop := componentSuppression(set, "ai", []string{l.ID, l.Name, l.Purl}, l.Evidence)
		if drop {
			dropped++
			continue
		}
		l.Evidence = kept
		libs = append(libs, l)
	}
	det.Libraries = libs

	models := det.Models[:0]
	for _, m := range det.Models {
		kept, drop := componentSuppression(set, "ai", []string{m.Name}, m.Evidence)
		if drop {
			dropped++
			continue
		}
		m.Occurrences, m.Evidence = adjustOccurrences(m.Occurrences, m.Evidence, kept), kept
		models = append(models, m)
	}
	det.Models = models

	infra := det.Infrastructure[:0]
	for _, i := range det.Infrastructure {
		kept, drop := componentSuppression(set, "ai", []string{i.ID, i.Name, i.Image}, i.Evidence)
		if drop {
			dropped++
			continue
		}
		i.Evidence = kept
		infra = append(infra, i)
	}
	det.Infrastructure = infra

	data := det.Data[:0]
	for _, d := range det.Data {
		kept, drop := componentSuppression(set, "ai", []string{d.Name, d.MountPath}, d.Evidence)
		if drop {
			dropped++
			continue
		}
		d.Evidence = kept
		data = append(data, d)
	}
	det.Data = data

	return dropped
}
