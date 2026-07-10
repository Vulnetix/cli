package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/triage"
)

// This file holds the machinery every scan-family subcommand shares to
// reconcile the findings it produced against the ones `.vulnetix/memory.yaml`
// remembers from prior runs, and to attest the resulting state changes as VEX.
//
// The contract, in one paragraph: a command records its current findings under
// a stable tool tag and deterministic ID, then asks memory which prior findings
// of that tool are no longer present. Records last seen on a different git
// branch are skipped. Records whose scanner recomputes its whole surface every
// run (sca, license, cbom, aibom, malscan) are resolved on absence alone;
// records anchored to a file+line (sast, secrets, iac, container) additionally
// need on-disk proof that the evidence is gone. Whatever resolves becomes a VEX
// statement in the channel that scanner owns.
//
// See `_system.md` → "Memory reconciliation and auto-VEX" for the decision tree.

// vulnetixDirFor resolves the .vulnetix directory for a scan root. Every caller
// must pass the same rootPath its scanner walked — the memory file belongs to
// the scanned tree, not to the process working directory. An empty rootPath
// means "the current directory", matching the --path flag default.
func vulnetixDirFor(rootPath string) string {
	if rootPath == "" {
		rootPath = "."
	}
	return filepath.Join(rootPath, ".vulnetix")
}

// toolVEXFile maps a tool tag to the OpenVEX artefact it writes inside
// .vulnetix/. SCA and license are absent: they attest through the CycloneDX VEX
// section of sbom.cdx.json instead (see cdxVEXForChanges).
var toolVEXFile = map[string]string{
	memory.ToolSAST:      "vex.openvex.json",
	memory.ToolSecrets:   "vex.openvex.json",
	memory.ToolIaC:       "vex.openvex.json",
	memory.ToolContainer: "vex.openvex.json",
	memory.ToolMalscan:   "vex-malscan.openvex.json",
	memory.ToolCBOM:      "vex-cbom.openvex.json",
	memory.ToolAIBOM:     "vex-aibom.openvex.json",
}

// vexFileTooling names the producer recorded in each OpenVEX document. Keyed by
// filename rather than by tool so the four static-analysis tools that share
// vex.openvex.json always agree on the tooling string.
var vexFileTooling = map[string]string{
	"vex.openvex.json":         "vulnetix-cli static-analysis",
	"vex-malscan.openvex.json": "vulnetix-cli malscan",
	"vex-cbom.openvex.json":    "vulnetix-cli cbom",
	"vex-aibom.openvex.json":   "vulnetix-cli aibom",
}

// reconcileOptions tunes a standalone reconciliation pass.
type reconcileOptions struct {
	// Mode overrides the tool's DefaultResolutionMode. Leave zero to inherit.
	Mode memory.ResolutionMode
	// RegressionStatus is the status a re-detected, previously-fixed record
	// returns to. Leave empty for "under_investigation".
	RegressionStatus string
	// IDPrefixes restricts which prior records may be resolved. Tools with
	// independently disableable detection passes pass the prefixes of the
	// passes that actually ran. Empty means every record of this tool.
	IDPrefixes []string
	// Verifier is required under memory.ResolveOnVerify and ignored otherwise.
	Verifier func(loc memory.Location) (gone bool, reason string)
}

// scanContextFor builds the branch/path stamp applied to every record written
// during this run. Branch is what gates cross-branch auto-resolution.
func scanContextFor(rootPath string, gitCtx *gitctx.GitContext) *memory.ScanContext {
	branch := ""
	if gitCtx != nil {
		branch = gitCtx.CurrentBranch
	}
	return &memory.ScanContext{Branch: branch, Path: rootPath}
}

// reconcileStandalone runs the full Load → Record → Reconcile → Save cycle for a
// command that owns its memory transaction end to end (license, cbom, aibom,
// malscan when invoked directly). It must not be used from inside runLocalScan,
// which loads memory once up front and saves it once at the end — see
// reconcileInto for that path.
//
// Callers gate on --disable-memory before invoking.
func reconcileStandalone(
	rootPath string,
	gitCtx *gitctx.GitContext,
	tool string,
	current map[string]memory.FindingRecord,
	opts reconcileOptions,
) []memory.StateChange {
	vulnetixDir := vulnetixDirFor(rootPath)
	mem, err := memory.Load(vulnetixDir)
	if err != nil || mem == nil {
		mem = &memory.Memory{Version: "1"}
	}
	mem.SetScanContext(scanContextFor(rootPath, gitCtx))

	changes := reconcileInto(mem, rootPath, gitCtx, tool, current, opts)

	if err := memory.Save(vulnetixDir, mem); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml: %v\n", err)
	}
	return changes
}

// reconcileInto records the current findings for tool into an already-loaded
// memory and reconciles them, returning the state changes. The caller owns
// saving.
func reconcileInto(
	mem *memory.Memory,
	rootPath string,
	gitCtx *gitctx.GitContext,
	tool string,
	current map[string]memory.FindingRecord,
	opts reconcileOptions,
) []memory.StateChange {
	if mem == nil {
		return nil
	}
	if len(current) > 0 {
		mem.RecordCategorizedFindings(tool, current)
	}
	currentIDs := make(map[string]bool, len(current))
	for id := range current {
		currentIDs[id] = true
	}
	branch := ""
	if gitCtx != nil {
		branch = gitCtx.CurrentBranch
	}
	return mem.ReconcileTool(memory.ReconcileContext{
		Tool:             tool,
		Mode:             opts.Mode,
		CurrentIDs:       currentIDs,
		Branch:           branch,
		RootPath:         rootPath,
		RegressionStatus: opts.RegressionStatus,
		IDPrefixes:       opts.IDPrefixes,
		Verifier:         opts.Verifier,
	})
}

// partitionChangesByTool groups state changes so each tool's transitions reach
// the VEX channel that tool owns. A change carrying no tool tag (legacy record)
// is attributed to SCA, which is where untagged findings historically came from.
func partitionChangesByTool(changes []memory.StateChange) map[string][]memory.StateChange {
	out := map[string][]memory.StateChange{}
	for _, sc := range changes {
		tool := sc.Tool
		if tool == "" {
			tool = memory.ToolSCA
		}
		out[tool] = append(out[tool], sc)
	}
	return out
}

// cdxVEXForChanges renders state changes as CycloneDX VEX vulnerabilities for
// the SBOM's `vulnerabilities` array. Used by the SCA and license channels.
func cdxVEXForChanges(changes []memory.StateChange, sourceName string) []cdx.Vulnerability {
	out := make([]cdx.Vulnerability, 0, len(changes))
	for _, sc := range changes {
		v := cdx.Vulnerability{
			BOMRef:   sc.CveID,
			ID:       sc.CveID,
			Source:   &cdx.Source{Name: sourceName},
			Analysis: cdx.AnalysisForStateChange(sc.NewStatus, sc.Comment),
			Properties: []cdx.Property{
				{Name: "vulnetix:vex-auto", Value: "true"},
			},
		}
		if sc.Package != "" {
			v.Properties = append(v.Properties, cdx.Property{Name: "vulnetix:package", Value: sc.Package})
		}
		out = append(out, v)
	}
	// Memory maps iterate in random order; sort so the BOM is reproducible.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// writeToolOpenVEX writes an OpenVEX 0.2.0 document attesting the state changes
// for a single tool, into that tool's artefact inside .vulnetix/. Returns "" and
// no error when there is nothing to attest, or when the tool attests through
// CycloneDX rather than OpenVEX.
func writeToolOpenVEX(rootPath, tool string, changes []memory.StateChange) (string, error) {
	fileName, ok := toolVEXFile[tool]
	if !ok {
		return "", nil
	}
	return writeOpenVEXFile(rootPath, fileName, changes)
}

// writeOpenVEXFile renders changes into the named OpenVEX artefact. Statements
// are sorted by identifier so repeated runs over an unchanged tree produce a
// byte-identical document — memory maps iterate in random order.
func writeOpenVEXFile(rootPath, fileName string, changes []memory.StateChange) (string, error) {
	if len(changes) == 0 {
		return "", nil
	}

	findings := make([]*triage.TriageFinding, 0, len(changes))
	for i := range changes {
		sc := changes[i]
		// Prefer the human-readable rule ID (carried as the first alias) over
		// the internal fingerprint for the OpenVEX vulnerability identifier.
		name := sc.CveID
		if len(sc.Finding.Aliases) > 0 && sc.Finding.Aliases[0] != "" {
			name = sc.Finding.Aliases[0]
		}
		tf := &triage.TriageFinding{
			CVEID:     name,
			Status:    sc.NewStatus,
			Severity:  sc.Finding.Severity,
			Package:   sc.Package,
			Ecosystem: sc.Ecosystem,
		}
		if sc.NewStatus == "fixed" && sc.Comment != "" {
			tf.ActionResponse = sc.Comment
		}
		findings = append(findings, tf)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].CVEID < findings[j].CVEID })

	tooling := vexFileTooling[fileName]
	if tooling == "" {
		tooling = "vulnetix-cli"
	}
	data, err := triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{Tooling: tooling})
	if err != nil {
		return "", err
	}

	path := filepath.Join(vulnetixDirFor(rootPath), fileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// writeOpenVEXForPartition writes one OpenVEX document per artefact, merging the
// tools that share vex.openvex.json into a single document rather than letting
// each truncate the last. Returns the artefact paths written, sorted.
func writeOpenVEXForPartition(rootPath string, byTool map[string][]memory.StateChange) []string {
	byFile := map[string][]memory.StateChange{}
	for tool, changes := range byTool {
		fileName, ok := toolVEXFile[tool]
		if !ok || len(changes) == 0 {
			continue
		}
		byFile[fileName] = append(byFile[fileName], changes...)
	}

	var paths []string
	for fileName, changes := range byFile {
		path, err := writeOpenVEXFile(rootPath, fileName, changes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write %s: %v\n", fileName, err)
			continue
		}
		if path != "" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}

// severityForPQC maps a CycloneDX PQC status onto the severity vocabulary the
// memory schema uses. Quantum-vulnerable and deprecated algorithms are real
// findings; the rest are inventory.
func severityForPQC(pqcStatus string) (severity, status string) {
	switch pqcStatus {
	case "quantum-vulnerable":
		return "high", "affected"
	case "deprecated":
		return "medium", "affected"
	case "hybrid":
		return "low", memory.StatusInventory
	default:
		return "info", memory.StatusInventory
	}
}
