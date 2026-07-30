package cmd

// SCA autofix internals — owned by the `fix` command (cmd/fix.go).
//
// These helpers were part of cmd/scan.go when `--sca-autofix` was the only entry
// point. They moved here unchanged when `vulnetix fix` became the owner: the scan
// family still triggers them through --sca-autofix, but the implementation lives
// with the command that is about remediation.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/display"
	autofix "github.com/vulnetix/cli/v3/internal/fix"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/triage"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

func printAutofixProposal(plans []autofix.FixCandidate, counts autofix.ProofCounts) {
	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, display.Divider(t))
	fmt.Fprintln(os.Stdout, display.Subheader(t, "SCA Autofix Dry Run"))
	if len(plans) == 0 {
		fmt.Fprintln(os.Stdout, "  No autofix candidates found.")
		return
	}
	for _, p := range plans {
		status := "will fix"
		if p.Skipped {
			status = "manual"
		}
		target := p.TargetVer
		if target == "" {
			target = "<no vetted target>"
		}
		fmt.Fprintf(os.Stdout, "  %s  %s %s -> %s  %s  %s\n",
			display.Bold(t, status),
			p.PackageName,
			p.CurrentVer,
			target,
			p.Method,
			display.Muted(t, p.SourceFile))
		if p.Reason != "" {
			fmt.Fprintf(os.Stdout, "    %s\n", p.Reason)
		}
		if p.SkipReason != "" {
			fmt.Fprintf(os.Stdout, "    skipped: %s\n", p.SkipReason)
		}
		if p.Command != "" {
			fmt.Fprintf(os.Stdout, "    $ %s\n", p.Command)
		}
	}
	printAutofixCounts(counts)
	fmt.Fprintln(os.Stdout, "  Dry run only: no manifests changed, no install ran, no rescan ran.")
	fmt.Fprintln(os.Stdout, display.Divider(t))
}

func printAutofixReport(plans []autofix.FixCandidate, counts autofix.ProofCounts, applied int, err error) {
	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, display.Divider(t))
	fmt.Fprintln(os.Stdout, display.Subheader(t, "SCA Autofix"))
	if err != nil {
		fmt.Fprintf(os.Stdout, "  %s %v\n", display.ErrorStyle(t, "failed:"), err)
	}
	if applied > 0 {
		fmt.Fprintf(os.Stdout, "  Resolved findings confirmed: %d\n", applied)
	}
	for _, p := range plans {
		if p.Skipped {
			fmt.Fprintf(os.Stdout, "  Not fixed: %s %s (%s)\n", p.PackageName, p.CurrentVer, p.SkipReason)
			if p.Command != "" {
				fmt.Fprintf(os.Stdout, "    manual: %s\n", p.Command)
			}
			if len(p.RejectedVersions) > 0 {
				fmt.Fprintf(os.Stdout, "    Rationale (safest strategy): no vulnerability-free version available\n")
				for _, rv := range p.RejectedVersions {
					marker := ""
					if rv.Version == p.CurrentVer {
						marker = "  ← installed"
					}
					switch {
					case rv.IsMalware:
						fmt.Fprintf(os.Stdout, "      • %s: malware%s\n", rv.Version, marker)
					case rv.ExplCount > 0:
						fmt.Fprintf(os.Stdout, "      • %s: %d vuln(s), %d exploit(s)%s\n", rv.Version, rv.VulnCount, rv.ExplCount, marker)
					default:
						fmt.Fprintf(os.Stdout, "      • %s: %d vuln(s)%s\n", rv.Version, rv.VulnCount, marker)
					}
				}
				latest := p.LatestAvailable
				if latest == "" {
					latest = p.CurrentVer
				}
				fmt.Fprintf(os.Stdout, "    Upgrading to latest (%s) would not reduce risk; staying at current version is risk-accepted.\n", latest)
			}
			continue
		}
		status := "Fixed"
		if err != nil {
			status = "Planned"
		}
		fmt.Fprintf(os.Stdout, "  %s: %s %s -> %s  %s  %s\n",
			status, p.PackageName, p.CurrentVer, p.TargetVer, p.Method, display.Muted(t, p.SourceFile))
		if p.Command != "" {
			fmt.Fprintf(os.Stdout, "    used: %s\n", p.Command)
		}
	}
	printAutofixCounts(counts)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "  %s Commit manifest and lockfile changes together.\n", display.Bold(t, "IMPORTANT:"))
	fmt.Fprintln(os.Stdout, "  Include the edited manifest and regenerated lockfile in the same commit.")
	fmt.Fprintln(os.Stdout, display.Divider(t))
}

func printAutofixCounts(counts autofix.ProofCounts) {
	fmt.Fprintf(os.Stdout, "  Proof-of-work: %d direct, %d transitive via parent-update, %d transitive via parent-upgrade, %d transitive via override, %d unresolved deep chains\n",
		counts.Direct, counts.TransitiveParentUpdate, counts.TransitiveParentUpgrade, counts.TransitiveOverride, counts.UnresolvedDeepChains)
}

func hasActionableAutofixPlan(plans []autofix.FixCandidate) bool {
	for _, p := range plans {
		if !p.Skipped {
			return true
		}
	}
	return false
}

func rewriteAutofixCommandsForPackageManagers(plans []autofix.FixCandidate, files []scan.DetectedFile) []autofix.FixCandidate {
	if len(plans) == 0 {
		return plans
	}
	presentFiles := make([]string, 0, len(files))
	for _, f := range files {
		if f.RelPath != "" {
			presentFiles = append(presentFiles, filepath.Base(f.RelPath))
		}
	}
	// Which resolver binaries are actually installed on this host, by ecosystem.
	detected := map[string]bool{}
	detectedByEcosystem := map[string][]string{}
	for _, rb := range scan.ResolvePackageManagerBinaries(presentFiles) {
		if rb.Detected {
			detected[rb.Binary] = true
			detectedByEcosystem[rb.Ecosystem] = append(detectedByEcosystem[rb.Ecosystem], rb.Binary)
		}
	}

	pmByDir := packageManagersByDir(files)
	yarnModernByDir := yarnModernByDir(files)
	out := append([]autofix.FixCandidate(nil), plans...)
	for i := range out {
		eco := strings.ToLower(out[i].Ecosystem)
		dir := filepath.Dir(filepath.Clean(out[i].SourceFile))
		pm := pmByDir[dir]
		if pm == "" {
			pm = defaultPackageManagerForEcosystem(eco)
		}
		// Prefer the lockfile-implied PM; if it is not installed, fall back to any
		// installed resolver for the same ecosystem. If none is installed we
		// cannot install/re-resolve, so mark the fix manual rather than emit a
		// command that will fail.
		if pm != "" && !detected[pm] {
			if alt := firstInstalledForEcosystem(eco, detectedByEcosystem); alt != "" {
				pm = alt
			} else if requiresInstalledManager(eco) && !out[i].Skipped {
				out[i].Skipped = true
				out[i].SkipReason = fmt.Sprintf("no %s package manager detected on PATH to apply and re-resolve the fix", eco)
				continue
			}
		}
		out[i].PackageManager = pm
		switch eco {
		case "npm":
			out[i].Command = npmCommandForManager(out[i], pm, yarnModernByDir[dir])
		case "pypi":
			out[i].Command = pythonCommandForManager(out[i], pm)
		}
	}
	return out
}

// defaultPackageManagerForEcosystem returns the conventional resolver when no
// lockfile narrowed the choice.
func defaultPackageManagerForEcosystem(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "npm"
	case "pypi":
		return "pip"
	case "golang":
		return "go"
	case "cargo":
		return "cargo"
	case "composer":
		return "composer"
	case "rubygems":
		return "bundle"
	case "maven":
		return "mvn"
	default:
		return ""
	}
}

func firstInstalledForEcosystem(ecosystem string, detectedByEcosystem map[string][]string) string {
	bins := detectedByEcosystem[ecosystem]
	if len(bins) == 0 {
		return ""
	}
	return bins[0]
}

// requiresInstalledManager reports whether applying a fix for the ecosystem
// requires an installed resolver to regenerate the lockfile.
func requiresInstalledManager(ecosystem string) bool {
	switch ecosystem {
	case "npm", "pypi", "golang", "cargo", "composer", "rubygems", "maven":
		return true
	default:
		return false
	}
}

func packageManagersByDir(files []scan.DetectedFile) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		dir := filepath.Dir(filepath.Clean(f.RelPath))
		base := filepath.Base(f.RelPath)
		switch base {
		case "package-lock.json":
			out[dir] = "npm"
		case "yarn.lock":
			out[dir] = "yarn"
		case "pnpm-lock.yaml":
			out[dir] = "pnpm"
		case "bun.lockb":
			out[dir] = "bun"
		case "uv.lock":
			out[dir] = "uv"
		case "poetry.lock":
			out[dir] = "poetry"
		case "pdm.lock":
			out[dir] = "pdm"
		case "Pipfile.lock":
			out[dir] = "pipenv"
		}
	}
	return out
}

func yarnModernByDir(files []scan.DetectedFile) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		dir := filepath.Dir(filepath.Clean(f.RelPath))
		base := filepath.Base(f.RelPath)
		if base == "package.json" && packageJSONDeclaresModernYarn(f.Path) {
			out[dir] = true
		}
		if base == "yarn.lock" && yarnLockIsModern(f.Path) {
			out[dir] = true
		}
		if base == "yarn.lock" && f.Path != "" {
			if _, err := os.Stat(filepath.Join(filepath.Dir(f.Path), ".yarnrc.yml")); err == nil {
				out[dir] = true
			}
		}
	}
	return out
}

func packageJSONDeclaresModernYarn(path string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var manifest struct {
		PackageManager string `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return false
	}
	pm := strings.ToLower(strings.TrimSpace(manifest.PackageManager))
	if !strings.HasPrefix(pm, "yarn@") {
		return false
	}
	ver := strings.TrimPrefix(pm, "yarn@")
	return ver != "" && !strings.HasPrefix(ver, "1.")
}

func yarnLockIsModern(path string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(data)
	if strings.Contains(text, "# yarn lockfile v1") {
		return false
	}
	return strings.Contains(text, "\n__metadata:") || strings.HasPrefix(text, "__metadata:")
}

func npmCommandForManager(p autofix.FixCandidate, pm string, modernYarn bool) string {
	name := p.PackageName
	if p.Method == autofix.MethodParentUpgrade && p.ParentName != "" {
		name = p.ParentName
	}
	switch p.Method {
	case autofix.MethodDirectBump, autofix.MethodOverride:
		switch pm {
		case "yarn", "pnpm", "bun":
			return pm + " install"
		default:
			return "npm install"
		}
	case autofix.MethodParentUpdate:
		if p.ParentName != "" {
			name = p.ParentName
		}
		switch pm {
		case "yarn":
			if modernYarn {
				return "yarn up " + name
			}
			return "yarn upgrade " + name
		case "pnpm", "bun":
			return pm + " update " + name
		default:
			return "npm update " + name
		}
	case autofix.MethodParentUpgrade:
		// Install the PARENT at its resolved version (ParentTarget), not the child's
		// safe version (TargetVer) — upgrading the parent is what pulls the safe child.
		target := p.ParentTarget
		if target == "" {
			target = "<safe-version>"
		}
		switch pm {
		case "yarn":
			if modernYarn {
				return "yarn up " + name + "@" + target
			}
			return "yarn add " + name + "@" + target
		case "pnpm", "bun":
			return pm + " add " + name + "@" + target
		default:
			return "npm install " + name + "@" + target
		}
	default:
		return p.Command
	}
}

func pythonCommandForManager(p autofix.FixCandidate, pm string) string {
	switch pm {
	case "uv":
		return "uv sync"
	case "poetry":
		return "poetry update " + p.PackageName
	case "pdm":
		return "pdm update " + p.PackageName
	case "pipenv":
		return "pipenv update " + p.PackageName
	default:
		return p.Command
	}
}

// scanAfterAutofix re-parses the (post-fix) manifests and re-queries the VDB to
// determine which vulnerabilities remain. It routes through the same self-healing
// /v2/cli.sca path as the primary scan (confirmation mode: no reachability,
// snapshot, or persistence) — there is no legacy per-PURL fallback.
func scanAfterAutofix(files []scan.DetectedFile) ([]scan.EnrichedVuln, error) {
	var allPackages []scan.ScopedPackage
	for _, f := range files {
		if f.FileType == scan.FileTypeCycloneDX {
			cdxBom, err := parseCDXForScan(f.Path)
			if err != nil {
				continue
			}
			pkgs := buildPackagesFromCDX(cdxBom.Components, f.RelPath)
			allPackages = append(allPackages, pkgs...)
			continue
		}
		if f.ManifestInfo == nil || !f.Supported {
			continue
		}
		pkgs, err := scan.ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
		if err != nil {
			continue
		}
		for i := range pkgs {
			pkgs[i].SourceFile = f.RelPath
		}
		allPackages = append(allPackages, pkgs...)
	}
	if len(allPackages) == 0 {
		return nil, nil
	}
	return confirmVulnsViaCliSCA(allPackages)
}

func resolvedAutofixFindings(plans []autofix.FixCandidate, after []scan.EnrichedVuln) []*triage.TriageFinding {
	remaining := map[string]bool{}
	for _, ev := range after {
		remaining[autofixFindingKey(ev.CveID, ev.PackageName, ev.Ecosystem)] = true
	}
	var findings []*triage.TriageFinding
	for _, p := range plans {
		if p.Skipped || p.TargetVer == "" {
			continue
		}
		for _, id := range p.CveIDs {
			if remaining[autofixFindingKey(id, p.PackageName, p.Ecosystem)] {
				continue
			}
			findings = append(findings, &triage.TriageFinding{
				CVEID:         id,
				Package:       p.PackageName,
				Ecosystem:     p.Ecosystem,
				InstalledVer:  p.CurrentVer,
				FixedVer:      p.TargetVer,
				Status:        "not_affected",
				Justification: "vulnerable_code_not_present",
			})
		}
	}
	return findings
}

func autofixFindingKey(cveID, packageName, ecosystem string) string {
	return strings.ToLower(cveID) + "::" + strings.ToLower(packageName) + "::" + strings.ToLower(ecosystem)
}

func writeAutofixVEX(root string, findings []*triage.TriageFinding) (string, error) {
	if len(findings) == 0 {
		return "", nil
	}
	data, err := triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{Tooling: "vulnetix-cli sca-autofix"})
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, ".vulnetix", "vex-autofix.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func postAutofixVEXToSnapshot(snapshotUuid string, persisted []vdb.CliFindingResult, findings []*triage.TriageFinding, plans []autofix.FixCandidate, counts autofix.ProofCounts, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, rootPath string, packages []scan.ScopedPackage, w io.Writer) {
	if snapshotUuid == "" || len(findings) == 0 || isUnauthenticatedScan() {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	client := newCliClient()
	if client == nil {
		return
	}

	byExact := map[string]vdb.CliFindingResult{}
	byPackage := map[string]vdb.CliFindingResult{}
	for _, f := range persisted {
		if f.FindingID == "" || f.PackageName == "" {
			continue
		}
		byPackage[autofixPersistedKey(f.FindingID, f.PackageName, "")] = f
		if f.PackageVersion != "" {
			byExact[autofixPersistedKey(f.FindingID, f.PackageName, f.PackageVersion)] = f
		}
	}

	planByFinding := map[string]autofix.FixCandidate{}
	for _, p := range plans {
		for _, id := range p.CveIDs {
			planByFinding[autofixFindingKey(id, p.PackageName, p.Ecosystem)] = p
		}
	}

	rows := make([]vdb.CliReachabilityPayload, 0, len(findings))
	for _, f := range findings {
		if f == nil || f.CVEID == "" || f.Package == "" {
			continue
		}
		persistedFinding := byExact[autofixPersistedKey(f.CVEID, f.Package, f.InstalledVer)]
		if persistedFinding.FindingUuid == "" {
			persistedFinding = byPackage[autofixPersistedKey(f.CVEID, f.Package, "")]
		}
		plan := planByFinding[autofixFindingKey(f.CVEID, f.Package, f.Ecosystem)]
		evidence, _ := json.Marshal(autofixEvidencePayload(f, plan, counts))
		rows = append(rows, vdb.CliReachabilityPayload{
			CveID:                  f.CVEID,
			FindingUuid:            persistedFinding.FindingUuid,
			PackageName:            f.Package,
			PackageVersion:         f.InstalledVer,
			Ecosystem:              f.Ecosystem,
			Source:                 "SYMBOL_FALLBACK",
			Verdict:                "UNREACHABLE",
			EvidenceJSON:           string(evidence),
			MemoryVexStatus:        "not_affected",
			MemoryVexJustification: "vulnerable_code_not_present",
			MemoryVexAction:        "fixed by vulnetix sca --sca-autofix",
			FixedVersion:           f.FixedVer,
		})
	}
	if len(rows) == 0 {
		return
	}

	env := buildCliEnv(gitCtx, sysInfo)
	enrichCliEnvForSCA(&env, rootPath, packages, gitCtx)
	resp, err := client.CliSCAReachability(env, vdb.CliSCAReachabilityRequest{
		IngestionSnapshotUuid: snapshotUuid,
		Results:               rows,
	})
	if err != nil {
		fmt.Fprintf(w, "  warning: autofix VEX publish failed: %v\n", err)
		return
	}
	if resp != nil && resp.Data.VEXUrl != "" {
		fmt.Fprintf(w, "  autofix VEX published: %s\n", resp.Data.VEXUrl)
	}
}

func autofixEvidencePayload(f *triage.TriageFinding, plan autofix.FixCandidate, counts autofix.ProofCounts) map[string]any {
	payload := map[string]any{
		"source":        "vulnetix-cli sca-autofix",
		"installed":     "",
		"fixed_version": "",
		"proof_of_work": map[string]int{
			"direct":                    counts.Direct,
			"transitive_parent_update":  counts.TransitiveParentUpdate,
			"transitive_parent_upgrade": counts.TransitiveParentUpgrade,
			"transitive_override":       counts.TransitiveOverride,
			"unresolved_deep_chains":    counts.UnresolvedDeepChains,
		},
	}
	if f != nil {
		payload["installed"] = f.InstalledVer
		payload["fixed_version"] = f.FixedVer
	}
	if plan.PackageName != "" {
		payload["package"] = plan.PackageName
		payload["ecosystem"] = plan.Ecosystem
		payload["method"] = string(plan.Method)
		payload["command"] = plan.Command
		payload["source_file"] = plan.SourceFile
		payload["target_version"] = plan.TargetVer
		payload["parent_name"] = plan.ParentName
		payload["parent_range"] = plan.ParentRange
		payload["parent_target"] = plan.ParentTarget
		payload["reason"] = plan.Reason
	}
	return payload
}

// skippedPlansWithNoSafeVersion returns the subset of plans that were skipped
// because no vulnerability-free Safe-Harbour version exists.
func skippedPlansWithNoSafeVersion(plans []autofix.FixCandidate) []autofix.FixCandidate {
	var out []autofix.FixCandidate
	for _, p := range plans {
		if p.Skipped && strings.Contains(p.SkipReason, "no Safe-Harbour") {
			out = append(out, p)
		}
	}
	return out
}

// writeRiskAcceptedVEX generates an OpenVEX document for packages that could
// not be fixed because every available version has vulnerabilities. The
// document records a risk-accepted decision and is written to
// .vulnetix/vex-risk-accepted.json.
func writeRiskAcceptedVEX(root string, skipped []autofix.FixCandidate, enrichedVulns []scan.EnrichedVuln) (string, error) {
	if len(skipped) == 0 {
		return "", nil
	}

	skipSet := map[string]bool{}
	for _, p := range skipped {
		skipSet[strings.ToLower(p.PackageName+"::"+p.Ecosystem)] = true
	}

	var findings []*triage.TriageFinding
	seen := map[string]bool{}
	for i := range enrichedVulns {
		v := &enrichedVulns[i]
		if !skipSet[strings.ToLower(v.PackageName+"::"+v.Ecosystem)] {
			continue
		}
		key := strings.ToLower(v.CveID + "::" + v.PackageName)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, &triage.TriageFinding{
			CVEID:          v.CveID,
			Package:        v.PackageName,
			Ecosystem:      v.Ecosystem,
			InstalledVer:   v.PackageVer,
			Status:         "affected",
			ActionResponse: "risk-accepted: no vulnerability-free version available under safest strategy",
		})
	}
	if len(findings) == 0 {
		return "", nil
	}

	data, err := triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{Tooling: "vulnetix-cli sca-autofix safest"})
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, ".vulnetix", "vex-risk-accepted.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// postRiskAcceptedVEXToSnapshot posts risk-acceptance VEX entries for packages
// that have no vulnerability-free Safe-Harbour version. Mirrors
// postAutofixVEXToSnapshot but uses Verdict "AFFECTED" and VEX status
// "affected" to record that the team is aware and has accepted the risk.
func postRiskAcceptedVEXToSnapshot(snapshotUuid string, persisted []vdb.CliFindingResult, skipped []autofix.FixCandidate, enrichedVulns []scan.EnrichedVuln, counts autofix.ProofCounts, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, rootPath string, packages []scan.ScopedPackage, w io.Writer) {
	if snapshotUuid == "" || len(skipped) == 0 || isUnauthenticatedScan() {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	client := newCliClient()
	if client == nil {
		return
	}

	byExact := map[string]vdb.CliFindingResult{}
	byPackage := map[string]vdb.CliFindingResult{}
	for _, f := range persisted {
		if f.FindingID == "" || f.PackageName == "" {
			continue
		}
		byPackage[autofixPersistedKey(f.FindingID, f.PackageName, "")] = f
		if f.PackageVersion != "" {
			byExact[autofixPersistedKey(f.FindingID, f.PackageName, f.PackageVersion)] = f
		}
	}

	skipSet := map[string]bool{}
	planByFinding := map[string]autofix.FixCandidate{}
	for _, p := range skipped {
		skipSet[strings.ToLower(p.PackageName+"::"+p.Ecosystem)] = true
		for _, id := range p.CveIDs {
			planByFinding[autofixFindingKey(id, p.PackageName, p.Ecosystem)] = p
		}
	}

	seen := map[string]bool{}
	var rows []vdb.CliReachabilityPayload
	for i := range enrichedVulns {
		v := &enrichedVulns[i]
		if !skipSet[strings.ToLower(v.PackageName+"::"+v.Ecosystem)] {
			continue
		}
		key := strings.ToLower(v.CveID + "::" + v.PackageName)
		if seen[key] {
			continue
		}
		seen[key] = true

		pf := byExact[autofixPersistedKey(v.CveID, v.PackageName, v.PackageVer)]
		if pf.FindingUuid == "" {
			pf = byPackage[autofixPersistedKey(v.CveID, v.PackageName, "")]
		}
		plan := planByFinding[autofixFindingKey(v.CveID, v.PackageName, v.Ecosystem)]
		f := &triage.TriageFinding{
			CVEID:        v.CveID,
			Package:      v.PackageName,
			Ecosystem:    v.Ecosystem,
			InstalledVer: v.PackageVer,
		}
		evidence, _ := json.Marshal(autofixEvidencePayload(f, plan, counts))
		rows = append(rows, vdb.CliReachabilityPayload{
			CveID:                  v.CveID,
			FindingUuid:            pf.FindingUuid,
			PackageName:            v.PackageName,
			PackageVersion:         v.PackageVer,
			Ecosystem:              v.Ecosystem,
			Source:                 "SAFE_HARBOUR_ANALYSIS",
			Verdict:                "AFFECTED",
			EvidenceJSON:           string(evidence),
			MemoryVexStatus:        "affected",
			MemoryVexJustification: "",
			MemoryVexAction:        "risk-accepted: no vulnerability-free version available under safest strategy",
		})
	}
	if len(rows) == 0 {
		return
	}

	env := buildCliEnv(gitCtx, sysInfo)
	enrichCliEnvForSCA(&env, rootPath, packages, gitCtx)
	resp, err := client.CliSCAReachability(env, vdb.CliSCAReachabilityRequest{
		IngestionSnapshotUuid: snapshotUuid,
		Results:               rows,
	})
	if err != nil {
		fmt.Fprintf(w, "  warning: risk-accepted VEX publish failed: %v\n", err)
		return
	}
	if resp != nil && resp.Data.VEXUrl != "" {
		fmt.Fprintf(w, "  risk-accepted VEX published: %s\n", resp.Data.VEXUrl)
	}
}

func autofixPersistedKey(cveID, packageName, version string) string {
	return strings.ToLower(cveID) + "::" + strings.ToLower(packageName) + "::" + version
}

func recordAutofixMemoryEvents(mem *memory.Memory, findings []*triage.TriageFinding) {
	if mem == nil || len(findings) == 0 {
		return
	}
	if mem.Findings == nil {
		mem.Findings = map[string]memory.FindingRecord{}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		if f == nil || f.CVEID == "" {
			continue
		}
		rec := mem.Findings[f.CVEID]
		if rec.Package == "" {
			rec.Package = f.Package
		}
		if rec.Ecosystem == "" {
			rec.Ecosystem = f.Ecosystem
		}
		rec.Status = "fixed"
		rec.Source = "vulnetix-sca"
		rec.Tool = memory.ToolSCA
		rec.Justification = "vulnerable_code_not_present"
		rec.ActionResponse = "fixed by vulnetix sca --sca-autofix"
		if rec.Versions == nil {
			rec.Versions = &memory.VersionInfo{}
		}
		if rec.Versions.Current == "" {
			rec.Versions.Current = f.InstalledVer
		}
		rec.Versions.FixedIn = f.FixedVer
		rec.Versions.FixSource = "sca-autofix"
		if rec.Remediation == nil {
			rec.Remediation = &memory.RemediationData{}
		}
		rec.Remediation.FixAvailability = "available"
		rec.Remediation.FixVersion = f.FixedVer

		detail := fmt.Sprintf("%s %s -> %s via vulnetix sca --sca-autofix", f.Package, f.InstalledVer, f.FixedVer)
		if !hasAutofixHistory(rec, detail) {
			rec.History = append(rec.History, memory.HistoryEntry{
				Date:   now,
				Event:  "autofix-applied",
				Detail: detail,
			})
		}
		mem.Findings[f.CVEID] = rec
	}
}

func hasAutofixHistory(rec memory.FindingRecord, detail string) bool {
	for _, h := range rec.History {
		if h.Event == "autofix-applied" && h.Detail == detail {
			return true
		}
	}
	return false
}
