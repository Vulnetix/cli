package cmd

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// --explain answers one question, so the run that answers it does only that
// work. Before this, `sca --explain requests` sent every package to the VDB and
// `scan --explain VNX-...` evaluated every rule and every dependency, and
// either one then wrote memory, the SBOM and SARIF and uploaded a snapshot as
// though it had been a real scan.
//
// The narrowing is decided from what the query names:
//   - a rule id: that rule alone runs (single-rule mode, as --rule-id), no SCA;
//   - a package, name@version or purl: only those packages are sent, no rules;
//   - an advisory id: the packages it affects, read from the last scan's SBOM
//     or asked of the VDB, are sent;
//   - anything else (a file path): the rules run and SCA is skipped.

// explainRuleModules loads the rule modules and reports the id of the rule the
// query names, "" when it names none. The modules are handed on so the packs
// are not fetched twice.
func explainRuleModules(query string, disableDefault bool, refs []sast.RuleRef, registry string, w io.Writer) (map[string]string, string) {
	modules, err := sast.LoadAllModules(sast.DefaultRulesFS, disableDefault, refs, registry, w)
	if err != nil || len(modules) == 0 {
		return modules, ""
	}
	for _, src := range sast.FilterModulesByID(modules, query) {
		if id := sast.ExtractRegoID(src); id != "" {
			return modules, id
		}
	}
	return modules, ""
}

// explainPackages returns the packages an --explain query names. matched is
// false when the query names no package and is not an advisory id, so the SCA
// round-trip has nothing to answer; resolved is false when it looks like an
// advisory id whose packages could not be learned, and the caller must ask
// about every package rather than miss the one it affects.
func explainPackages(pkgs []scan.ScopedPackage, query, rootPath string) (out []scan.ScopedPackage, matched, resolved bool) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return pkgs, true, true
	}
	for _, p := range pkgs {
		name := strings.ToLower(p.Name)
		purl := strings.ToLower(cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem))
		if name == q || name+"@"+strings.ToLower(p.Version) == q || (purl != "" && purl == q) {
			out = append(out, p)
		}
	}
	if len(out) > 0 {
		return out, true, true
	}
	if !looksLikeAdvisoryID(q) {
		return nil, false, true
	}
	names := advisoryPackagesFromSBOM(filepath.Join(rootPath, ".vulnetix", "sbom.cdx.json"), q)
	if len(names) == 0 {
		names = advisoryPackagesFromVDB(query)
	}
	if len(names) == 0 {
		return pkgs, true, false
	}
	for _, p := range pkgs {
		if names[strings.ToLower(p.Name)] {
			out = append(out, p)
		}
	}
	return out, true, true
}

// looksLikeAdvisoryID reports whether q is shaped like CVE-2024-1234,
// GHSA-xxxx-xxxx-xxxx, PYSEC-2024-38 or GO-2024-1234: a letter prefix, a dash,
// and a digit somewhere after it. A package name rarely is; a path never is.
func looksLikeAdvisoryID(q string) bool {
	if strings.ContainsAny(q, "/@ ") {
		return false
	}
	i := strings.Index(q, "-")
	if i <= 0 || q[:i] == "vnx" {
		// VNX- is this CLI's own rule namespace, never an advisory.
		return false
	}
	for _, r := range q[:i] {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return strings.ContainsAny(q[i:], "0123456789")
}

// advisoryPackagesFromSBOM reads the packages an advisory affects from the SBOM
// the last scan wrote. Read only: an explain run never writes it.
func advisoryPackagesFromSBOM(path, q string) map[string]bool {
	bom, err := parseCDXForScan(path)
	if err != nil || bom == nil {
		return nil
	}
	byRef := map[string]string{}
	for _, c := range bom.Components {
		if c.BOMRef != "" {
			byRef[c.BOMRef] = strings.ToLower(c.Name)
		}
	}
	out := map[string]bool{}
	for _, v := range bom.Vulnerabilities {
		if !strings.EqualFold(v.ID, q) && !referencesID(v.Extra["references"], q) {
			continue
		}
		for _, a := range v.Affects {
			if n := byRef[a.Ref]; n != "" {
				out[n] = true
			}
		}
	}
	return out
}

// referencesID reports whether a CycloneDX references array names id, which is
// where the aliases of a folded advisory live.
func referencesID(raw json.RawMessage, id string) bool {
	if len(raw) == 0 {
		return false
	}
	var refs []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &refs) != nil {
		return false
	}
	for _, r := range refs {
		if strings.EqualFold(r.ID, id) {
			return true
		}
	}
	return false
}

// advisoryPackagesFromVDB asks the VDB which packages an advisory affects: one
// request, against sending every package the project has.
func advisoryPackagesFromVDB(id string) map[string]bool {
	data, err := newEnrichmentClient().V2Affected(id, vdb.V2QueryParams{})
	if err != nil {
		return nil
	}
	affected, _ := data["affected"].([]any)
	out := map[string]bool{}
	for _, a := range affected {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"packageName", "product"} {
			if n := stringVal(am, key); n != "" {
				out[strings.ToLower(n)] = true
			}
		}
	}
	return out
}

// explainProgress is where the explain pre-pass reports rule loading.
func explainProgress() io.Writer {
	if silent {
		return io.Discard
	}
	return os.Stderr
}

// explainRequested reports whether cmd was asked to --explain, for the passes
// that run outside runScanWithFeatures (AIBOM, CBOM, the container ELF pass):
// each uploads, and none of them explains anything.
func explainRequested(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetString("explain")
	return strings.TrimSpace(v) != ""
}
