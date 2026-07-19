package cmd

import (
	"path/filepath"
	"time"

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
					FilePath:           s.FilePath,
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
