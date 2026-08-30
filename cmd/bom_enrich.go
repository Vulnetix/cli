package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/bom"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/cdxsign"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// ─────────────────────────────────────────────────────────────────────────
// bom_enrich.go — taking a supplied SBOM and giving it back better.
//
// An SBOM from a build tool says what is in an artefact and very little else:
// component names, versions, sometimes a licence. What a consumer needs is the
// same document with the licences resolved, the known vulnerabilities attached,
// and the VEX statements applied — and still standards-valid, so it remains an
// SBOM rather than becoming a Vulnetix report.
//
// Two properties this must not lose.
//
// Fidelity: enrichment rewrites a document somebody else signed. The original's
// digest is recorded on the output, and --keep-original writes the input beside
// it, so the enriched document can always be traced back to what it was made
// from. A transformation that cannot be traced is indistinguishable from a
// substitution.
//
// Attribution: the output is re-signed with THIS machine's identity, not the
// original signer's, because this machine is what made these claims. The
// original signature is preserved as an external reference rather than
// discarded — it attests the input, which is still a fact worth carrying.
// ─────────────────────────────────────────────────────────────────────────

// Property names recording what enrichment did.
const (
	// PropEnrichedFrom is the digest of the document this was made from.
	PropEnrichedFrom = "vulnetix:bom/enriched-from"
	// PropEnrichedAt is when.
	PropEnrichedAt = "vulnetix:bom/enriched-at"
	// PropEnrichedBy is the tool and version that did it.
	PropEnrichedBy = "vulnetix:bom/enriched-by"
	// PropOriginalSignature points at the input's preserved signature.
	PropOriginalSignature = "vulnetix:bom/original-signature"
)

var bomEnrichCmd = &cobra.Command{
	Use:   "enrich <file>",
	Short: "Resolve licences, attach vulnerabilities and VEX to a supplied SBOM",
	Long: `Take an SBOM somebody else produced and give it back better.

Three passes, each independently skippable:

  licences  resolve components whose licence is absent or NOASSERTION, through
            deps.dev, the ecosystem registries and GitHub — the same resolvers
            'vulnetix license' uses
  vulns     attach known vulnerabilities from the Vulnetix VDB as CycloneDX
            vulnerability entries, with ratings, EPSS and KEV context
  vex       apply VEX statements from --vex, so the document carries the
            analysis as well as the findings

The output is a standards-valid CycloneDX document — still an SBOM, not a
report. A companion OpenVEX file is written beside it when VEX was applied, so
consumers that want the statements separately have them.

Enrichment rewrites a document somebody else may have signed, so the original's
digest is always recorded on the output and --keep-original writes the input
beside it. With --sign the result is signed with this machine's own identity,
because this machine is what made these claims; any signature on the input is
preserved as an external reference rather than discarded.

Examples:
  vulnetix bom enrich sbom.spdx.json -o enriched.cdx.json
  vulnetix bom enrich sbom.cdx.json -o enriched.cdx.json --vex vendor.openvex.json
  vulnetix bom enrich sbom.cdx.json -o enriched.cdx.json --no-vulns
  vulnetix bom enrich sbom.cdx.json -o enriched.cdx.json --keep-original --sign`,
	Args:         cobra.ExactArgs(1),
	RunE:         runBOMEnrich,
	SilenceUsage: true,
}

// BOMEnrichOptions is the options struct for the enrichment pass.
type BOMEnrichOptions struct {
	// InputPath is the document to enrich.
	InputPath string
	// OutPath receives the enriched document.
	OutPath string
	// VEXPaths are VEX documents to apply.
	VEXPaths []string
	// NoLicenses, NoVulns and NoVEX skip a pass.
	NoLicenses, NoVulns, NoVEX bool
	// KeepOriginal writes the input beside the output.
	KeepOriginal bool
	// Sign re-signs the result with this machine's ambient identity.
	Sign bool
}

// BOMEnrichResult reports what enrichment changed.
type BOMEnrichResult struct {
	Document *bom.Document `json:"-"`
	// LicensesResolved is how many components gained a licence.
	LicensesResolved int `json:"licensesResolved"`
	// VulnerabilitiesAttached is how many entries were added.
	VulnerabilitiesAttached int `json:"vulnerabilitiesAttached"`
	// VEX carries the total/effective/suppressed split when VEX was applied.
	VEX *VEXPassResult `json:"-"`
	// Written names every file produced.
	Written []string `json:"written,omitempty"`
	// Warnings are passes that degraded rather than failed.
	Warnings []string `json:"warnings,omitempty"`
	// Signature is the outcome of re-signing, when asked for.
	Signature cdxsign.Result `json:"-"`
}

func runBOMEnrich(cmd *cobra.Command, args []string) error {
	outPath, _ := cmd.Flags().GetString("out")
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	if outPath == "" {
		return fmt.Errorf("--out is required: enrichment produces a new document rather than rewriting the input")
	}
	vexPaths, _ := cmd.Flags().GetStringArray("vex")
	noLicenses, _ := cmd.Flags().GetBool("no-licenses")
	noVulns, _ := cmd.Flags().GetBool("no-vulns")
	noVEX, _ := cmd.Flags().GetBool("no-vex")
	keepOriginal, _ := cmd.Flags().GetBool("keep-original")
	sign, _ := cmd.Flags().GetBool("sign")

	res, err := runBOMEnrichPass(cmd, BOMEnrichOptions{
		InputPath: args[0], OutPath: outPath, VEXPaths: vexPaths,
		NoLicenses: noLicenses, NoVulns: noVulns, NoVEX: noVEX,
		KeepOriginal: keepOriginal, Sign: sign,
	})
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		payload := map[string]any{
			"source":                  res.Document.Source,
			"licensesResolved":        res.LicensesResolved,
			"vulnerabilitiesAttached": res.VulnerabilitiesAttached,
			"written":                 res.Written,
			"warnings":                res.Warnings,
		}
		if res.VEX != nil {
			payload["vex"] = res.VEX.Result
		}
		return emitJSON(payload)
	}
	renderEnrich(res)
	return nil
}

// runBOMEnrichPass is the shared entry point for enrichment.
func runBOMEnrichPass(cmd *cobra.Command, opts BOMEnrichOptions) (*BOMEnrichResult, error) {
	// Through runBOMImport, so an SPDX or attestation-wrapped input is enriched
	// exactly like a bare CycloneDX one.
	imported, err := runBOMImport(BOMImportOptions{Path: opts.InputPath})
	if err != nil {
		return nil, err
	}
	doc := imported.Document
	res := &BOMEnrichResult{Document: doc}

	if !opts.NoLicenses {
		resolved, warn := enrichLicenses(doc.BOM)
		res.LicensesResolved = resolved
		res.Warnings = append(res.Warnings, warn...)
	}

	if !opts.NoVulns {
		attached, warn := enrichVulnerabilities(cmd, doc.BOM)
		res.VulnerabilitiesAttached = attached
		res.Warnings = append(res.Warnings, warn...)
	}

	if !opts.NoVEX && len(opts.VEXPaths) > 0 {
		pass, vexErr := runVEXPass(VEXPassOptions{Paths: opts.VEXPaths, BOM: doc.BOM})
		if vexErr != nil {
			return nil, fmt.Errorf("applying --vex: %w", vexErr)
		}
		res.VEX = pass
	}

	stampEnrichment(doc)

	if err := writeEnriched(res, doc, opts); err != nil {
		return nil, err
	}
	return res, nil
}

// enrichLicenses resolves components whose licence is absent or NOASSERTION.
//
// Reuses license.DetectLicenses, the same resolver `vulnetix license` uses, so
// an enriched document's licences agree with what a scan of the same tree would
// report. A component whose licence was already stated is left alone: the
// document's own claim is better evidence than a registry lookup.
func enrichLicenses(b *cdx.BOM) (int, []string) {
	var (
		unresolved []scan.ScopedPackage
		byKey      = map[string]*cdx.Component{}
	)
	for i := range b.Components {
		c := &b.Components[i]
		if hasStatedLicense(c) || c.Name == "" {
			continue
		}
		eco := componentEcosystem(c)
		if eco == "" {
			continue
		}
		key := strings.ToLower(c.Name) + "@" + c.Version
		byKey[key] = c
		unresolved = append(unresolved, scan.ScopedPackage{
			Name: c.Name, Version: c.Version, Ecosystem: eco,
		})
	}
	if len(unresolved) == 0 {
		return 0, nil
	}

	resolved := 0
	for _, pkg := range license.DetectLicenses(unresolved, nil) {
		if pkg.LicenseSpdxID == "" || pkg.LicenseSpdxID == "UNKNOWN" {
			continue
		}
		c, ok := byKey[strings.ToLower(pkg.PackageName)+"@"+pkg.PackageVersion]
		if !ok {
			continue
		}
		// license.id is schema-constrained to the SPDX enum, so an unrecognised
		// value has to travel as a free-form name or the document stops
		// validating.
		if canonical := license.CanonicalSPDXID(pkg.LicenseSpdxID); canonical != "" {
			c.Licenses = []cdx.LicenseChoice{{License: &cdx.LicenseData{ID: canonical}}}
		} else {
			c.Licenses = []cdx.LicenseChoice{{License: &cdx.LicenseData{Name: pkg.LicenseSpdxID}}}
		}
		c.Properties = append(c.Properties, cdx.Property{
			Name: "vulnetix:license/resolved-by", Value: pkg.LicenseSource,
		})
		resolved++
	}
	return resolved, nil
}

// hasStatedLicense reports whether a component already claims a licence.
func hasStatedLicense(c *cdx.Component) bool {
	for _, lc := range c.Licenses {
		if lc.Expression != "" {
			return true
		}
		if lc.License != nil && (lc.License.ID != "" || lc.License.Name != "") {
			return true
		}
	}
	return false
}

// componentEcosystem reads a component's ecosystem from its purl.
func componentEcosystem(c *cdx.Component) string {
	if c.Purl == "" {
		return ""
	}
	rest, ok := strings.CutPrefix(c.Purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.Index(rest, "/"); i > 0 {
		return rest[:i]
	}
	return ""
}

// enrichVulnerabilities attaches known vulnerabilities from the VDB.
//
// Best-effort: a document enriched with licences and VEX is still more useful
// than none, so an unreachable or unauthenticated VDB degrades to a warning
// rather than failing the command.
func enrichVulnerabilities(cmd *cobra.Command, b *cdx.BOM) (int, []string) {
	purls := make([]string, 0, len(b.Components))
	seen := map[string]bool{}
	for i := range b.Components {
		p := b.Components[i].Purl
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		purls = append(purls, p)
	}
	if len(purls) == 0 {
		return 0, []string{"no component carries a purl, so no vulnerability lookup was possible"}
	}

	before := len(b.Vulnerabilities)
	if err := attachVDBVulnerabilities(cmd, b, purls); err != nil {
		return 0, []string{"vulnerability lookup: " + err.Error()}
	}
	return len(b.Vulnerabilities) - before, nil
}

// stampEnrichment records what was done, so the output can be traced back.
// stampEnrichment records this pass on a document somebody else authored.
//
// This is the transformer tier, and the distinction is the whole point.
// CycloneDX describes metadata.tools as "the tool(s) used in the creation,
// enrichment, and validation of the BOM", so an enricher belongs in that table —
// but metadata.manufacturer and metadata.authors say who *created* the document,
// and enriching syft's SBOM does not make us its author. Those are left as
// found, along with the original tool entries.
//
// The output is written to a new path, so it is a new artefact: NextRevision
// mints a serialNumber for it and records the one it derived from, which is what
// keeps the chain followable after the identity changes.
func stampEnrichment(doc *bom.Document) {
	if doc.BOM.Metadata == nil {
		doc.BOM.Metadata = &cdx.Metadata{}
	}
	_ = cyclonedx.AppendToolParticipation(doc.BOM, cdx.Participating(cyclonedx.ToolBOMEnrich))
	_ = cyclonedx.NextRevision(doc.BOM, "")

	set := func(name, value string) {
		if value == "" {
			return
		}
		doc.BOM.Metadata.SetProperty(name, value)
	}
	set(PropEnrichedFrom, "sha256:"+doc.Source.Digest)
	set(PropEnrichedAt, time.Now().UTC().Format(time.RFC3339))
	set(PropEnrichedBy, "vulnetix-cli/"+version)
}

// writeEnriched writes the enriched document and its companions.
func writeEnriched(res *BOMEnrichResult, doc *bom.Document, opts BOMEnrichOptions) error {
	if dir := filepath.Dir(opts.OutPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	// The input is copied before the output is signed, because the signature
	// covers the output and a later write must not change what was signed.
	if opts.KeepOriginal {
		original, err := os.ReadFile(opts.InputPath)
		if err != nil {
			return err
		}
		originalPath := opts.OutPath + ".original" + filepath.Ext(opts.InputPath)
		if err := os.WriteFile(originalPath, original, 0o644); err != nil {
			return err
		}
		res.Written = append(res.Written, originalPath)
	}

	// A signature on the input attests the input, which stays true after
	// enrichment — so it is preserved as a reference rather than discarded.
	preserveOriginalSignature(res, doc, opts)

	data, err := json.MarshalIndent(doc.BOM, "", "  ")
	if err != nil {
		return err
	}

	if opts.Sign {
		signed, serr := cdxsign.SignDocument(cmdContext(), opts.OutPath, data)
		if serr != nil {
			// An enriched document is worth publishing unsigned; losing it over
			// a signing failure would be the worse outcome.
			res.Warnings = append(res.Warnings, "signing: "+serr.Error())
		} else {
			res.Signature = signed
			data = signed.Document
			res.Written = append(res.Written, signed.Files...)
			if !signed.Signed() && signed.Skipped != "" {
				res.Warnings = append(res.Warnings, "not signed: "+signed.Skipped)
			}
		}
	}

	if err := os.WriteFile(opts.OutPath, append(data, '\n'), 0o644); err != nil {
		return err
	}
	res.Written = append([]string{opts.OutPath}, res.Written...)

	// The companion VEX exists so a consumer that wants the statements
	// separately does not have to extract them from the analysis blocks.
	if res.VEX != nil && res.VEX.Statements > 0 {
		if err := writeCompanionVEX(res, opts); err != nil {
			res.Warnings = append(res.Warnings, "companion VEX: "+err.Error())
		}
	}
	return nil
}

// preserveOriginalSignature records the input's signature on the output.
func preserveOriginalSignature(res *BOMEnrichResult, doc *bom.Document, opts BOMEnrichOptions) {
	for _, suffix := range []string{".intoto.jsonl", ".sig"} {
		path := opts.InputPath + suffix
		if !fileExists(path) {
			continue
		}
		// Upsert, not append: this used to append unconditionally, so
		// re-enriching a document left it asserting the same property twice with
		// different values, which a consumer resolves by picking one arbitrarily.
		doc.BOM.Metadata.SetProperty(PropOriginalSignature, filepath.Base(path))
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%s signs the input, not this enriched document; it is recorded as %s",
			filepath.Base(path), PropOriginalSignature))
		return
	}
}

// writeCompanionVEX writes the applied statements beside the enriched document.
func writeCompanionVEX(res *BOMEnrichResult, opts BOMEnrichOptions) error {
	statements := make([]vexStatementForCompanion, 0)
	for _, a := range res.VEX.Result.Applied {
		statements = append(statements, vexStatementForCompanion{
			VulnID: a.VulnID, Purl: a.Purl, Status: string(a.Status), Explain: a.Explain,
		})
	}
	if len(statements) == 0 {
		return nil
	}

	path := strings.TrimSuffix(opts.OutPath, filepath.Ext(opts.OutPath)) + ".openvex.json"
	data, err := companionOpenVEX(statements)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return err
	}
	res.Written = append(res.Written, path)
	return nil
}

func renderEnrich(res *BOMEnrichResult) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "SBOM enrichment"))
	fmt.Println()

	src := res.Document.Source
	rows := [][]string{
		{"Input", fmt.Sprintf("%s %s", src.Format, src.SpecVersion)},
		{"Input digest", "sha256:" + shortDigest(src.Digest)},
		{"Components", fmt.Sprintf("%d", len(res.Document.BOM.Components))},
		{"Licences resolved", fmt.Sprintf("%d", res.LicensesResolved)},
		{"Vulnerabilities attached", fmt.Sprintf("%d", res.VulnerabilitiesAttached)},
	}
	if res.VEX != nil && res.VEX.Result != nil {
		rows = append(rows, []string{"VEX suppressed",
			fmt.Sprintf("%d of %d", res.VEX.Result.Suppressed, res.VEX.Result.Total)})
	}
	// Identity, not Signed(): a zero-value cdxsign.Result has an empty Skipped
	// and so reports itself as signed, which would put a blank "Signed as" row
	// on every run that never asked to sign.
	if res.Signature.Identity != "" {
		rows = append(rows, []string{"Signed as", res.Signature.Identity})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Field", MinWidth: 26},
		{Header: "Value"},
	}, rows))
	fmt.Print("\n\n")

	for _, w := range res.Warnings {
		fmt.Printf("%s %s\n", display.WarningMark(term), display.Muted(term, w))
	}
	if len(res.Warnings) > 0 {
		fmt.Println()
	}

	for _, f := range res.Written {
		fmt.Printf("%s %s\n", display.CheckMark(term), display.Bold(term, f))
	}
}

// shortDigest truncates a digest for display.
func shortDigest(d string) string {
	if len(d) > 16 {
		return d[:16] + "…"
	}
	return d
}

func init() {
	bomCmd.AddCommand(bomEnrichCmd)

	bomEnrichCmd.Flags().String("out", "", "Write the enriched CycloneDX document here (required)")
	bomEnrichCmd.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	bomEnrichCmd.Flags().StringArray("vex", nil, "VEX file or directory to apply (repeatable)")
	bomEnrichCmd.Flags().Bool("no-licenses", false, "Skip licence resolution")
	bomEnrichCmd.Flags().Bool("no-vulns", false, "Skip the vulnerability lookup")
	bomEnrichCmd.Flags().Bool("no-vex", false, "Skip VEX application")
	bomEnrichCmd.Flags().Bool("keep-original", false, "Write the input document beside the output")
	bomEnrichCmd.Flags().Bool("sign", false,
		"Sign the enriched document with this machine's own OIDC identity (CI runners)")
}

// vexStatementForCompanion is the shape the companion document carries.
type vexStatementForCompanion struct {
	VulnID  string
	Purl    string
	Status  string
	Explain string
}
