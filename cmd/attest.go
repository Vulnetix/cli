package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/attest"
	"github.com/vulnetix/cli/v3/internal/display"
)

// ─────────────────────────────────────────────────────────────────────────
// attest.go — verifying signatures and provenance on artefacts we consume.
//
// internal/cdxsign signs; internal/attest reads those signatures back, and
// anyone else's. runAttestVerify is the shared entry point, so `attest verify`
// and `bom import --verify-attestation` apply the same checks — a document
// trusted by one path and not the other would be worse than neither.
//
// The output is a per-check table, never a bare tick. A verifier that reports
// success for a check it did not perform converts an unknown into a false
// assurance, which is the one thing worse than not verifying at all.
// ─────────────────────────────────────────────────────────────────────────

var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Verify signatures and provenance on artefacts",
	Long: `Verify the signatures and in-toto provenance on an artefact.

Reads what 'vulnetix cdx --sign' writes — a DSSE envelope and cosign-compatible
detached sidecars — and anything else in those formats.

What is checked, and what is not, is always stated. Signature validity and the
certificate's identity are checked locally. Certificate chain validation happens
only when you supply a trusted root, and is reported as skipped otherwise, not
quietly passed. Rekor transparency-log inclusion is never checked here: it needs
the log's public key and an online query, and claiming it without doing it would
be a lie the output cannot recover from.

For the full Sigstore verification path, use 'cosign verify-blob'. This command
is what a scan can honestly do offline, said precisely.

Subcommands:
  verify  check an artefact's signature, identity and provenance`,
	SilenceUsage: true,
}

var attestVerifyCmd = &cobra.Command{
	Use:   "verify <artifact>",
	Short: "Verify an artefact's signature, identity and provenance",
	Long: `Verify an artefact's signature and report what its provenance claims.

Sidecars are discovered beside the artefact unless named explicitly:
<artifact>.intoto.jsonl for the DSSE envelope, <artifact>.sig and
<artifact>.pem for the detached cosign pair.

--identity is a regular expression the certificate subject must match, and
--issuer the OIDC issuer it must name. Without them a valid signature proves
only that somebody signed it, which is rarely the question being asked.

--trusted-root enables certificate chain validation. Without it, the certificate
is read but not proven to come from a CA you trust, and the report says so.
--require makes a skipped check a failure, so a pipeline that genuinely needs
chain validation is told when it did not happen instead of reading a pass.

Exits 1 when any performed check failed, or when a required check was skipped.

Examples:
  vulnetix attest verify sbom.cdx.json
  vulnetix attest verify sbom.cdx.json --identity 'https://github.com/acme/.*'
  vulnetix attest verify sbom.cdx.json --issuer https://token.actions.githubusercontent.com
  vulnetix attest verify sbom.cdx.json --trusted-root fulcio.pem --require certificate-chain
  vulnetix attest verify sbom.cdx.json -o json`,
	Args:         cobra.ExactArgs(1),
	RunE:         runAttestVerifyCmd,
	SilenceUsage: true,
}

// AttestVerifyOptions is the options struct for the one entry point into
// attestation verification.
type AttestVerifyOptions struct {
	// ArtifactPath is the file to verify.
	ArtifactPath string
	// SignaturePath, CertificatePath and EnvelopePath override sidecar
	// discovery. Empty means "look beside the artefact".
	SignaturePath, CertificatePath, EnvelopePath string
	// Identity is a regexp the certificate subject must match.
	Identity string
	// Issuer is the OIDC issuer the certificate must name.
	Issuer string
	// TrustedRootPath enables certificate chain validation.
	TrustedRootPath string
	// Require names checks that must have been performed.
	Require []string
}

// runAttestVerify verifies an artefact. The shared entry point; `bom import
// --verify-attestation` calls it too.
func runAttestVerify(opts AttestVerifyOptions) (*attest.Result, error) {
	data, err := os.ReadFile(opts.ArtifactPath)
	if err != nil {
		return nil, err
	}

	envelope := opts.EnvelopePath
	signature := opts.SignaturePath
	certificate := opts.CertificatePath

	// Sidecar discovery, only for what the caller did not name. The suffixes
	// are the ones internal/cdxsign writes and stock cosign expects, so a user
	// does not have to learn a second convention.
	if envelope == "" && signature == "" {
		if p := opts.ArtifactPath + ".intoto.jsonl"; fileExists(p) {
			envelope = p
		}
		if p := opts.ArtifactPath + ".sig"; envelope == "" && fileExists(p) {
			signature = p
		}
	}
	if signature != "" && certificate == "" {
		if p := opts.ArtifactPath + ".pem"; fileExists(p) {
			certificate = p
		}
	}
	if envelope == "" && signature == "" {
		return nil, fmt.Errorf(
			"no signature found for %s: expected %s.intoto.jsonl or %s.sig beside it, "+
				"or name one with --envelope / --signature",
			opts.ArtifactPath, filepath.Base(opts.ArtifactPath), filepath.Base(opts.ArtifactPath))
	}

	return attest.Verify(attest.Options{
		ArtifactPath:    opts.ArtifactPath,
		Artifact:        data,
		SignaturePath:   signature,
		CertificatePath: certificate,
		EnvelopePath:    envelope,
		Identity:        opts.Identity,
		Issuer:          opts.Issuer,
		TrustedRootPath: opts.TrustedRootPath,
		Require:         opts.Require,
	})
}

func runAttestVerifyCmd(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	envelope, _ := cmd.Flags().GetString("envelope")
	signature, _ := cmd.Flags().GetString("signature")
	certificate, _ := cmd.Flags().GetString("certificate")
	identity, _ := cmd.Flags().GetString("identity")
	issuer, _ := cmd.Flags().GetString("issuer")
	trustedRoot, _ := cmd.Flags().GetString("trusted-root")
	require, _ := cmd.Flags().GetStringArray("require")

	res, err := runAttestVerify(AttestVerifyOptions{
		ArtifactPath:    args[0],
		EnvelopePath:    envelope,
		SignaturePath:   signature,
		CertificatePath: certificate,
		Identity:        identity,
		Issuer:          issuer,
		TrustedRootPath: trustedRoot,
		Require:         require,
	})
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		if err := emitJSON(map[string]any{
			"result":   res,
			"verified": res.Verified(),
		}); err != nil {
			return err
		}
	} else {
		renderAttestResult(res)
	}

	if failures := res.Failures(); len(failures) > 0 {
		names := make([]string, 0, len(failures))
		for _, f := range failures {
			names = append(names, f.Name)
		}
		return &bomGateError{
			gate:    "attest",
			message: "attestation verification failed: " + strings.Join(names, ", "),
		}
	}
	return nil
}

func renderAttestResult(res *attest.Result) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "Attestation"))
	fmt.Println()
	fmt.Printf("Artifact: %s\n", display.Bold(term, res.Artifact))
	if res.Digest != "" {
		fmt.Printf("Digest:   sha256:%s\n", res.Digest)
	}
	fmt.Printf("Envelope: %s\n", orDash(res.Envelope))
	fmt.Println()

	if res.Identity.Subject != "" || res.Identity.Issuer != "" {
		fmt.Println(display.Subheader(term, "Signed by"))
		rows := [][]string{
			{"Subject", orDash(res.Identity.Subject)},
			{"Issuer", orDash(res.Identity.Issuer)},
		}
		if res.Identity.SourceRepository != "" {
			rows = append(rows, []string{"Source repo", res.Identity.SourceRepository})
		}
		if res.Identity.SourceRevision != "" {
			rows = append(rows, []string{"Source revision", res.Identity.SourceRevision})
		}
		if !res.Identity.NotBefore.IsZero() {
			rows = append(rows, []string{"Certificate valid",
				res.Identity.NotBefore.Format("2006-01-02T15:04:05Z") + " → " +
					res.Identity.NotAfter.Format("2006-01-02T15:04:05Z")})
		}
		fmt.Print(display.Table(term, []display.Column{
			{Header: "Field", MinWidth: 18},
			{Header: "Value"},
		}, rows))
		fmt.Print("\n\n")
	}

	// The check table is the output. A single verdict line would hide which
	// assurances were actually obtained.
	fmt.Println(display.Subheader(term, "Checks"))
	rows := make([][]string, 0, len(res.Checks))
	for _, c := range res.Checks {
		rows = append(rows, []string{string(c.Status), c.Name, c.Detail})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Result", MinWidth: 8, Color: attestStatusColour(term)},
		{Header: "Check", MinWidth: 22},
		{Header: "Detail"},
	}, rows))
	fmt.Print("\n\n")

	if res.Predicate != nil {
		renderPredicate(term, res.Predicate)
	}

	switch {
	case len(res.Failures()) > 0:
		fmt.Printf("%s %s failed.\n", display.CrossMark(term),
			pluralise("check", len(res.Failures())))
	case res.Verified():
		// "N checks" then a separate verb, because pluralise() appends its "s"
		// to the whole phrase it is given.
		fmt.Printf("%s Signature verified. %s were not performed — see the table above.\n",
			display.CheckMark(term), pluralise("check", len(res.Missing())))
	default:
		fmt.Printf("%s Nothing was verified.\n", display.WarningMark(term))
	}
}

func renderPredicate(term *display.Terminal, p *attest.Predicate) {
	fmt.Println(display.Subheader(term, "Provenance (claimed, not verified)"))

	rows := [][]string{{"Predicate type", p.Type}}
	if p.SLSAVersion != "" {
		rows = append(rows, []string{"SLSA version", p.SLSAVersion})
	}
	if p.Builder != "" {
		rows = append(rows, []string{"Builder", p.Builder})
	}
	if p.BuildType != "" {
		rows = append(rows, []string{"Build type", p.BuildType})
	}
	if p.SourceURI != "" {
		rows = append(rows, []string{"Source", p.SourceURI})
	}
	if p.SourceRevision != "" {
		rows = append(rows, []string{"Revision", p.SourceRevision})
	}
	for _, s := range p.Subjects {
		rows = append(rows, []string{"Subject", s.Name + " " + firstSubjectDigest(s)})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Field", MinWidth: 18},
		{Header: "Value"},
	}, rows))
	fmt.Print("\n\n")

	if claim := p.Claim(); !claim.Complete() && len(claim.Missing) > 0 {
		fmt.Printf("%s Provenance is incomplete: no %s.\n",
			display.WarningMark(term), strings.Join(claim.Missing, ", no "))
		fmt.Println()
	}
}

// firstSubjectDigest renders a subject's digest for display.
func firstSubjectDigest(s attest.Subject) string {
	if v, ok := s.Digest["sha256"]; ok {
		return "sha256:" + v
	}
	for alg, v := range s.Digest {
		return alg + ":" + v
	}
	return ""
}

// attestStatusColour styles a check result.
//
// A skipped check is styled as a warning, not as neutral: it is an assurance the
// reader might otherwise assume they have.
func attestStatusColour(term *display.Terminal) func(string) string {
	return func(cell string) string {
		switch attest.CheckStatus(strings.TrimSpace(cell)) {
		case attest.CheckPassed:
			return display.Success(term, cell)
		case attest.CheckFailed:
			return display.ErrorStyle(term, cell)
		default:
			return display.Muted(term, cell)
		}
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func init() {
	attestCmd.AddCommand(attestVerifyCmd)
	rootCmd.AddCommand(attestCmd)

	attestVerifyCmd.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	attestVerifyCmd.Flags().String("envelope", "", "DSSE envelope (default: <artifact>.intoto.jsonl)")
	attestVerifyCmd.Flags().String("signature", "", "Detached signature (default: <artifact>.sig)")
	attestVerifyCmd.Flags().String("certificate", "", "Signing certificate (default: <artifact>.pem)")
	attestVerifyCmd.Flags().String("identity", "", "Regular expression the certificate subject must match")
	attestVerifyCmd.Flags().String("issuer", "", "OIDC issuer the certificate must name")
	attestVerifyCmd.Flags().String("trusted-root", "",
		"PEM bundle to validate the certificate chain against (also SIGSTORE_ROOT_FILE)")
	attestVerifyCmd.Flags().StringArray("require", nil,
		"Treat this check as a failure if it was not performed, e.g. certificate-chain (repeatable)")
}
