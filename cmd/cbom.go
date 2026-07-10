package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/cbom"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var cbomCmd = &cobra.Command{
	Use:   "cbom [path]",
	Short: "Discover cryptographic usage and emit a CycloneDX CBOM with PQC posture",
	Long: `Discover cryptographic algorithms, certificates and crypto libraries used in a
project — in source code and configuration — and produce a Cryptography Bill of
Materials (CBOM) in CycloneDX format. Each algorithm is classified for
post-quantum posture (quantum-safe, quantum-vulnerable, deprecated or hybrid),
carries its NIST quantum-security level and an annotated per-country approval
matrix (NIST, CNSA 2.0, BSI, ACSC, CCCS, NUKIB, AIVD, NCSC, KpqC).

Four detection passes, all driven by a maintainable catalog:
  • source code — per-language crypto API usage (Go crypto/*, Python hashlib /
                  pyca, Java JCA, Node crypto, …) plus generic call extractors.
                  Algorithm spellings are case/separator-insensitive: SHA256,
                  Sha256, sha256 and SHA_256 all resolve to one SPDX algorithm.
  • config      — TLS cipher suites & versions, SSH Ciphers/KexAlgorithms/MACs,
                  JWT alg, OpenSSL/IPsec settings.
  • certificates— X.509 certificates and keys on disk (signature algorithm, key
                  type & size, validity). Only metadata is read, never key bytes.
  • dependencies— declared crypto libraries (OpenSSL, Bouncy Castle, libsodium,
                  liboqs, ring, Tink, pyca/cryptography, …).

The catalog is embedded and can be extended or replaced at runtime with
--catalog. No source content is ever uploaded.

The CycloneDX CBOM is always written to .vulnetix/cbom.cdx.json (override the
path with --output-file). The terminal output format is set by -o. Use --fail-on
to make CI exit non-zero when quantum-vulnerable or deprecated crypto is found.

Detected assets are tracked in .vulnetix/memory.yaml. An asset that disappears
from a later scan is marked resolved and attested in
.vulnetix/vex-cbom.openvex.json. Pass --disable-memory to turn this off.

Examples:
  vulnetix cbom                                   # pretty summary; writes .vulnetix/cbom.cdx.json
  vulnetix cbom ./service -o json                 # print detections as JSON
  vulnetix cbom -o cyclonedx-json                 # print CycloneDX to stdout (still saved to file)
  vulnetix cbom --no-certs --no-deps              # source + config only
  vulnetix cbom --fail-on quantum-vulnerable      # gate CI on quantum-vulnerable crypto
  vulnetix cbom --catalog ./extra-algos.json      # extend the builtin catalog`,
	Args:         cobra.MaximumNArgs(1),
	RunE:         runCBOM,
	SilenceUsage: true,
}

func init() {
	cbomCmd.Flags().String("path", ".", "Directory to scan")
	cbomCmd.Flags().Int("depth", 25, "Maximum recursion depth for file discovery")
	cbomCmd.Flags().StringArray("ignore", nil, "Exclude paths matching glob pattern (repeatable)")
	cbomCmd.Flags().StringP("output", "o", "pretty", "Terminal output format: pretty, json, cyclonedx-json")
	cbomCmd.Flags().String("output-file", "", "Path to write the CycloneDX CBOM (default: <path>/.vulnetix/cbom.cdx.json)")
	cbomCmd.Flags().String("spec-version", "1.7", "CycloneDX spec version: 1.6 or 1.7")
	cbomCmd.Flags().String("catalog", "", "Path to a catalog file to merge over (or replace) the builtin catalog")
	cbomCmd.Flags().Bool("no-builtin-catalog", false, "Do not load the embedded catalog (use only --catalog)")
	cbomCmd.Flags().Bool("no-source", false, "Skip the source-code crypto API detection pass")
	cbomCmd.Flags().Bool("no-config", false, "Skip the config & protocol detection pass")
	cbomCmd.Flags().Bool("no-certs", false, "Skip the certificate / key detection pass")
	cbomCmd.Flags().Bool("no-deps", false, "Skip the crypto-library detection pass")
	cbomCmd.Flags().String("fail-on", "none", "Exit non-zero when crypto of these PQC statuses is found: none, quantum-vulnerable, deprecated (comma-separated)")
	cbomCmd.Flags().Bool("no-upload", false, "Do not submit the CBOM to Vulnetix (it is submitted automatically when authenticated)")
	cbomCmd.Flags().Bool("cbom-include-ignored", false, "Include files matched by .gitignore (default: gitignored paths are skipped)")
	rootCmd.AddCommand(cbomCmd)
}

func runCBOM(cmd *cobra.Command, args []string) error {
	rootPath, _ := cmd.Flags().GetString("path")
	if len(args) == 1 && args[0] != "" {
		rootPath = args[0]
	}
	depth, _ := cmd.Flags().GetInt("depth")
	ignore, _ := cmd.Flags().GetStringArray("ignore")
	outputFmt, _ := cmd.Flags().GetString("output")
	outputFile, _ := cmd.Flags().GetString("output-file")
	specVersion, _ := cmd.Flags().GetString("spec-version")
	catalogPath, _ := cmd.Flags().GetString("catalog")
	noBuiltin, _ := cmd.Flags().GetBool("no-builtin-catalog")
	noSource, _ := cmd.Flags().GetBool("no-source")
	noConfig, _ := cmd.Flags().GetBool("no-config")
	noCerts, _ := cmd.Flags().GetBool("no-certs")
	noDeps, _ := cmd.Flags().GetBool("no-deps")
	failOnRaw, _ := cmd.Flags().GetString("fail-on")
	noUpload, _ := cmd.Flags().GetBool("no-upload")
	includeIgnored, _ := cmd.Flags().GetBool("cbom-include-ignored")

	switch outputFmt {
	case "pretty", "table", "json", "cyclonedx-json":
	default:
		return fmt.Errorf("--output must be one of: pretty, json, cyclonedx-json")
	}
	switch specVersion {
	case "1.6", "1.7":
	default:
		return fmt.Errorf("--spec-version must be one of: 1.6, 1.7")
	}
	failOn, err := parseFailOn(failOnRaw)
	if err != nil {
		return err
	}

	cat, err := cbom.LoadCatalog(catalogPath, noBuiltin)
	if err != nil {
		return err
	}
	compiled, err := cat.Compile()
	if err != nil {
		return fmt.Errorf("invalid CBOM catalog: %w", err)
	}

	det, err := cbom.Detect(cbom.Options{
		Root:             rootPath,
		MaxDepth:         depth,
		Ignore:           ignore,
		ScanSource:       !noSource,
		ScanConfig:       !noConfig,
		ScanCerts:        !noCerts,
		ScanDeps:         !noDeps,
		Catalog:          compiled,
		RespectGitignore: !includeIgnored,
	})
	if err != nil {
		return err
	}

	// Build the CycloneDX CBOM once — used for both cyclonedx-json output and the
	// backend submission. Build + validate live in the shared vdb-cyclonedx module.
	gitCtx := gitctx.Collect(rootPath)
	bomData, err := cyclonedx.BuildCBOM(det, cyclonedx.CBOMOptions{
		SpecVersion: specVersion,
		ToolName:    "vulnetix-cbom",
		ToolVersion: version,
		Project:     aibomProject(gitCtx, gitctx.CollectSystemInfo()),
	})
	if err != nil {
		return err
	}

	// Memory always lives under the resolved scan root, never the process CWD.
	reconcileCBOMMemory(rootPath, gitCtx, det, cbomPasses{
		Source: !noSource, Config: !noConfig, Certs: !noCerts, Deps: !noDeps,
	})

	if !noUpload {
		uploadCBOM(specVersion, det, bomData, gitCtx)
	}

	warnOutputExtension(outputFile, ".cdx.json")
	outFile := outputFile
	if outFile == "" {
		outFile = filepath.Join(rootPath, ".vulnetix", "cbom.cdx.json")
	}
	if err := writeCBOMFile(outFile, bomData); err != nil {
		return err
	}

	switch outputFmt {
	case "json":
		data, err := json.MarshalIndent(det, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(data))
	case "cyclonedx-json":
		fmt.Fprintln(os.Stdout, string(bomData))
	default: // pretty / table
		if err := renderCBOMTable(cmd, det); err != nil {
			return err
		}
	}

	return evaluateFailOn(det.Summary, failOn)
}

// cbomFindingRecords converts a CBOM detection result into memory records.
//
// The identifiers are synthetic but deterministic. Algorithm names are already
// canonicalised project-wide by internal/cbom/normalize.go (SHA256, Sha256 and
// SHA_256 collapse to one asset), so the key needs no file or line component —
// occurrences and evidence carry the locations.
//
// Most of a CBOM is inventory, not a defect list: recording every detected
// SHA-256 as `under_investigation` would drown the triage queue. Only
// quantum-vulnerable and deprecated algorithms are recorded as `affected`; the
// rest carry memory.StatusInventory, which is invisible to the open-findings
// queries but still auto-resolves (with VEX) when the algorithm leaves the code.
func cbomFindingRecords(det cyclonedx.CryptoDetections) map[string]memory.FindingRecord {
	out := make(map[string]memory.FindingRecord,
		len(det.Assets)+len(det.Certificates)+len(det.Libraries))

	firstEvidenceLocation := func(ev []cyclonedx.CryptoEvidence) []memory.Location {
		for _, e := range ev {
			if e.Locator != "" {
				return []memory.Location{{File: e.Locator, Snippet: e.Snippet}}
			}
		}
		return nil
	}

	for _, a := range det.Assets {
		name := a.SPDXID
		if name == "" {
			name = a.Name
		}
		// No Aliases: the synthetic key is the identifier that reaches the
		// OpenVEX statement, and the bare algorithm name would be ambiguous
		// across primitives.
		severity, status := severityForPQC(a.PQCStatus)
		out[fmt.Sprintf("CBOM:asset:%s:%s", name, a.Primitive)] = memory.FindingRecord{
			Severity:  severity,
			Status:    status,
			Source:    "vulnetix-cbom",
			Locations: firstEvidenceLocation(a.Evidence),
		}
	}

	for _, c := range det.Certificates {
		key := fmt.Sprintf("CBOM:cert:%s:%s:%s", c.Subject, c.Issuer, c.NotAfter)
		if c.Subject == "" && c.Issuer == "" {
			key = "CBOM:cert:" + c.Name
		}
		severity, status := severityForPQC(c.PQCStatus)
		out[key] = memory.FindingRecord{
			Severity:  severity,
			Status:    status,
			Source:    "vulnetix-cbom",
			Locations: firstEvidenceLocation(c.Evidence),
		}
	}

	for _, l := range det.Libraries {
		id := l.ID
		if id == "" {
			id = l.Name
		}
		out[fmt.Sprintf("CBOM:lib:%s:%s", id, l.Provider)] = memory.FindingRecord{
			Package:   l.Name,
			Severity:  "info",
			Status:    memory.StatusInventory,
			Source:    "vulnetix-cbom",
			Locations: firstEvidenceLocation(l.Evidence),
		}
	}

	return out
}

// cbomPasses records which of the four CBOM detection passes ran, so that a
// pass the user disabled cannot resolve the findings it would have produced.
type cbomPasses struct {
	Source bool
	Config bool
	Certs  bool
	Deps   bool
}

// cbomReconcileScope maps the passes that ran onto the finding-ID prefixes that
// may participate in reconciliation. Algorithms surface from the source and
// config passes together, so both must have run before an asset may be resolved.
func cbomReconcileScope(p cbomPasses) []string {
	var prefixes []string
	if p.Source && p.Config {
		prefixes = append(prefixes, "CBOM:asset:")
	}
	if p.Certs {
		prefixes = append(prefixes, "CBOM:cert:")
	}
	if p.Deps {
		prefixes = append(prefixes, "CBOM:lib:")
	}
	// An empty prefix list would mean "reconcile everything". When no pass is
	// eligible we must reconcile nothing, so return a prefix that matches no
	// record rather than none at all.
	if len(prefixes) == 0 {
		return []string{"\x00none"}
	}
	return prefixes
}

// reconcileCBOMMemory records the detected cryptographic inventory and resolves
// anything that has left the codebase since the last run, attesting resolutions
// in .vulnetix/vex-cbom.openvex.json.
//
// It must run even when the current detection is empty — that is precisely the
// case where every prior asset should be resolved.
func reconcileCBOMMemory(rootPath string, gitCtx *gitctx.GitContext, det cyclonedx.CryptoDetections, passes cbomPasses) {
	if disableMemory {
		return
	}
	changes := reconcileStandalone(rootPath, gitCtx, memory.ToolCBOM,
		cbomFindingRecords(det), reconcileOptions{
			Mode: memory.ResolveOnAbsence,
			// A re-detected algorithm returns to inventory, not to the triage
			// queue — its reappearance is not a finding to investigate.
			RegressionStatus: memory.StatusInventory,
			IDPrefixes:       cbomReconcileScope(passes),
		})
	if vexPath, err := writeToolOpenVEX(rootPath, memory.ToolCBOM, changes); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not write CBOM OpenVEX: %v\n", err)
	} else if vexPath != "" && !silent {
		fmt.Fprintf(os.Stderr, "  VEX: %s\n", vexPath)
	}
}

// detectAndUploadCBOM runs the CBOM detection passes against rootPath, reconciles
// the result against local memory, and submits it to the backend. Best-effort:
// silent on any error and never affects the caller's exit code. Used by `scan` to
// capture cryptographic inventory (PQC posture) alongside the rest of the scan.
// The submission is skipped when no cryptography is detected (no empty
// snapshots), but reconciliation still runs — an empty detection is exactly when
// prior assets must be resolved.
func detectAndUploadCBOM(rootPath string, gitCtx *gitctx.GitContext) {
	if rootPath == "" {
		rootPath = "."
	}
	cat, err := cbom.LoadCatalog("", false)
	if err != nil {
		return
	}
	compiled, err := cat.Compile()
	if err != nil {
		return
	}
	det, err := cbom.Detect(cbom.Options{
		Root:       rootPath,
		ScanSource: true,
		ScanConfig: true,
		ScanCerts:  true,
		ScanDeps:   true,
		Catalog:    compiled,
	})
	if err != nil {
		return
	}
	reconcileCBOMMemory(rootPath, gitCtx, det, cbomPasses{
		Source: true, Config: true, Certs: true, Deps: true,
	})
	if len(det.Assets)+len(det.Certificates)+len(det.Libraries) == 0 {
		return
	}
	data, err := cyclonedx.BuildCBOM(det, cyclonedx.CBOMOptions{
		SpecVersion: "1.7",
		ToolName:    "vulnetix-cbom",
		ToolVersion: version,
		Project:     aibomProject(gitCtx, gitctx.CollectSystemInfo()),
	})
	if err != nil {
		return
	}
	uploadCBOM("1.7", det, data, gitCtx)
}

// parseFailOn validates the --fail-on selection.
func parseFailOn(raw string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(strings.ToLower(tok))
		switch tok {
		case "", "none":
			continue
		case cyclonedx.PQCQuantumVulnerable, cyclonedx.PQCDeprecated, cyclonedx.PQCHybrid, cyclonedx.PQCQuantumSafe:
			out[tok] = true
		default:
			return nil, fmt.Errorf("--fail-on: unknown status %q (want none, quantum-vulnerable, deprecated, hybrid, quantum-safe)", tok)
		}
	}
	return out, nil
}

// evaluateFailOn returns a non-zero (error) result when the summary contains any
// of the selected PQC statuses.
func evaluateFailOn(s cyclonedx.CryptoSummary, failOn map[string]bool) error {
	counts := map[string]int{
		cyclonedx.PQCQuantumVulnerable: s.QuantumVulnerable,
		cyclonedx.PQCDeprecated:        s.Deprecated,
		cyclonedx.PQCHybrid:            s.Hybrid,
		cyclonedx.PQCQuantumSafe:       s.QuantumSafe,
	}
	var breached []string
	for status := range failOn {
		if counts[status] > 0 {
			breached = append(breached, fmt.Sprintf("%d %s", counts[status], status))
		}
	}
	if len(breached) == 0 {
		return nil
	}
	sort.Strings(breached)
	return fmt.Errorf("cbom gate failed: found %s", strings.Join(breached, ", "))
}

// uploadCBOM submits the CBOM to POST /v2/cli.cbom. Best-effort: community /
// unauthenticated callers are skipped and any error is non-fatal.
func uploadCBOM(specVersion string, det cyclonedx.CryptoDetections, bomData []byte, git *gitctx.GitContext) {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		return
	}
	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	if client.HTTPClient != nil {
		client.HTTPClient.Timeout = 180 * time.Second
	}
	detJSON, err := json.Marshal(det)
	if err != nil {
		return
	}
	env := envForCliWithGit(git)
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "vulnetix-cbom",
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}
	resp, err := client.CliCBOM(env, vdb.CliCBOMRequest{
		SpecVersion:    specVersion,
		CatalogVersion: det.CatalogVersion,
		BomJSON:        string(bomData),
		Detections:     detJSON,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "cbom: upload failed: %v\n", err)
		}
		return
	}
	if resp != nil && resp.Data.Cbom != nil && resp.Data.Cbom.URL != "" && !silent {
		fmt.Fprintf(os.Stderr, "Cryptography Inventory: %s\n", resp.Data.Cbom.URL)
	}
}

func writeCBOMFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "Wrote CBOM to %s\n", path)
	}
	return nil
}

func renderCBOMTable(cmd *cobra.Command, det cyclonedx.CryptoDetections) error {
	dctx := display.FromCommand(cmd)
	if dctx.IsJSON() {
		data, err := json.MarshalIndent(det, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	t := display.NewTerminal()
	var b strings.Builder
	b.WriteString(display.Header(t, "Cryptography Bill of Materials"))
	b.WriteByte('\n')
	s := det.Summary
	fmt.Fprintf(&b, "  Catalog %s — %d algorithm(s), %d certificate(s), %d library(ies)\n",
		det.CatalogVersion, len(det.Assets), len(det.Certificates), len(det.Libraries))
	fmt.Fprintf(&b, "  PQC posture: %d quantum-vulnerable, %d deprecated, %d hybrid, %d quantum-safe\n\n",
		s.QuantumVulnerable, s.Deprecated, s.Hybrid, s.QuantumSafe)

	if len(det.Assets) > 0 {
		b.WriteString(display.Header(t, "Algorithms"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Assets))
		for _, a := range det.Assets {
			rows = append(rows, []string{
				a.Name, a.Primitive, a.PQCStatus, strconv.Itoa(a.NISTQuantumSecurityLevel),
				standardsSummary(a.Standards), strconv.Itoa(a.Occurrences),
			})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Algorithm"}, {Header: "Primitive"}, {Header: "PQC Status"},
			{Header: "Q-Level", Align: display.AlignRight}, {Header: "Standards"},
			{Header: "Uses", Align: display.AlignRight},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(det.Certificates) > 0 {
		b.WriteString(display.Header(t, "Certificates"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Certificates))
		for _, c := range det.Certificates {
			rows = append(rows, []string{c.Name, c.PublicKeyAlgorithm, keySize(c.KeySize), c.PQCStatus, c.NotAfter})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "File"}, {Header: "Key Algorithm"}, {Header: "Key Size", Align: display.AlignRight},
			{Header: "PQC Status"}, {Header: "Not After"},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(det.Libraries) > 0 {
		b.WriteString(display.Header(t, "Crypto Libraries"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(det.Libraries))
		for _, l := range det.Libraries {
			rows = append(rows, []string{l.Name, l.Provider, strings.Join(l.Languages, ", ")})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Library"}, {Header: "Provider"}, {Header: "Languages"},
		}, rows))
		b.WriteString("\n")
	}

	if len(det.Assets) == 0 && len(det.Certificates) == 0 && len(det.Libraries) == 0 {
		b.WriteString("  No cryptographic usage detected.\n")
	}

	fmt.Print(b.String())
	return nil
}

func standardsSummary(m map[string]string) string {
	if len(m) == 0 {
		return "-"
	}
	bodies := make([]string, 0, len(m))
	for k := range m {
		bodies = append(bodies, k)
	}
	sort.Strings(bodies)
	parts := make([]string, 0, len(bodies))
	for _, b := range bodies {
		parts = append(parts, b+":"+m[b])
	}
	return strings.Join(parts, " ")
}

func keySize(n int) string {
	if n <= 0 {
		return "-"
	}
	return strconv.Itoa(n)
}
