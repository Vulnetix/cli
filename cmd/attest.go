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
// The defaults do the work: the Sigstore public-good root is embedded, so a
// chain is validated without being asked. What could not be established is said
// once, with the command that would establish it — never as a wall of skipped
// checks the reader has to decode.
// ─────────────────────────────────────────────────────────────────────────

var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Verify signatures and provenance on artefacts",
	Long: `Verify the signatures and in-toto provenance on an artefact.

Reads what 'vulnetix cdx --sign' writes — a DSSE envelope and cosign-compatible
detached sidecars — and anything else in those formats.

Run it with no flags. The Sigstore public-good root is built in, so the
certificate chain is validated by default, exactly as cosign does it. The output
says who signed the artefact and, if the check could be tighter, the one command
that would tighten it.

Subcommands:
  verify  check an artefact's signature, identity and provenance`,
	SilenceUsage: true,
}

var attestVerifyCmd = &cobra.Command{
	Use:   "verify <artifact>",
	Short: "Verify an artefact's signature, identity and provenance",
	Long: `Verify an artefact's signature and report what its provenance claims.

Run it with no flags:

  vulnetix attest verify sbom.cdx.json

Sidecars are found beside the artefact — <artifact>.intoto.jsonl for a DSSE
envelope, <artifact>.sig and <artifact>.pem for the detached cosign pair.

The signature and the certificate chain are checked by default, against the
built-in Sigstore public-good root. A valid signature means somebody Sigstore
trusts made it — which, for GitHub Actions, is any workflow in any repository.
To require a particular signer, pin the identity; the command prints the exact
flag with the identity it found, so you can paste it back:

  vulnetix attest verify sbom.cdx.json --identity 'https://github.com/acme/repo/...'

--issuer pins the OIDC provider. --trusted-root points at a private Sigstore
deployment's root instead of the built-in one. --require <check> fails the run
when a named check did not happen, for a pipeline that needs a specific
assurance rather than the default set.

Exits 1 when any check fails.

Examples:
  vulnetix attest verify sbom.cdx.json
  vulnetix attest verify sbom.cdx.json --identity 'https://github.com/acme/.*'
  vulnetix attest verify sbom.cdx.json --trusted-root private-fulcio.pem
  vulnetix attest verify sbom.cdx.json --verbose      # show every check
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

// renderAttestResult prints the verdict.
//
// Shaped for somebody who has never verified a signature before: the answer
// first in one line, then what was established, then — only if there is
// something to do — the exact command that would tighten it. The earlier
// version led with a six-row table of which four rows said "skipped", which
// told a non-expert they had failed at something without saying at what.
func renderAttestResult(res *attest.Result) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "Attestation"))
	fmt.Println()

	// The verdict, first and in one line.
	switch {
	case len(res.Failures()) > 0:
		fmt.Printf("%s %s could not be verified.\n\n",
			display.CrossMark(term), display.Bold(term, filepath.Base(res.Artifact)))
	case res.Verified():
		fmt.Printf("%s %s is signed, and the signature is valid.\n\n",
			display.CheckMark(term), display.Bold(term, filepath.Base(res.Artifact)))
	default:
		fmt.Printf("%s %s carries no signature this CLI could check.\n\n",
			display.WarningMark(term), display.Bold(term, filepath.Base(res.Artifact)))
	}

	// Who signed it, as prose rather than a field dump. This is the fact a
	// reader most wants and the one they are least able to assemble from a
	// certificate.
	if res.Identity.Subject != "" {
		fmt.Println(display.Subheader(term, "Signed by"))
		fmt.Printf("  %s\n", display.Bold(term, res.Identity.Subject))
		if res.Identity.Issuer != "" {
			fmt.Printf("  %s\n", display.Muted(term,
				"authenticated by "+res.Identity.Issuer))
		}
		if res.TrustAnchor != "" && res.PerformedChain() {
			fmt.Printf("  %s\n", display.Muted(term,
				"certificate issued by "+res.TrustAnchor))
		}
		fmt.Println()
	}

	renderAttestChecks(term, res)

	if res.Predicate != nil {
		renderPredicate(term, res.Predicate)
	}

	// Failures get the detail; a passing run does not need to be lectured.
	if failures := res.Failures(); len(failures) > 0 {
		fmt.Println(display.Subheader(term, "Why it failed"))
		for _, f := range failures {
			fmt.Printf("  %s %s\n", display.ErrorStyle(term, f.Name+":"), f.Detail)
		}
		fmt.Println()
		return
	}

	renderAttestSuggestions(term, res)
}

// renderAttestChecks prints the check table only when it adds something.
//
// A run where everything passed does not need six rows saying so — the verdict
// line already said it. --verbose, or any failure, brings the table back.
func renderAttestChecks(term *display.Terminal, res *attest.Result) {
	if !verbose && len(res.Failures()) == 0 {
		return
	}
	rows := make([][]string, 0, len(res.Checks))
	for _, c := range res.Checks {
		rows = append(rows, []string{string(c.Status), c.Name, c.Detail})
	}
	if len(rows) == 0 {
		return
	}
	fmt.Println(display.Subheader(term, "Checks"))
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Result", MinWidth: 8, Color: attestStatusColour(term)},
		{Header: "Check", MinWidth: 22},
		{Header: "Detail"},
	}, rows))
	fmt.Print("\n\n")
}

// renderAttestSuggestions prints how to make the verification stricter.
//
// Each one is a complete command, not a description of a flag. Somebody who has
// never written a certificate-identity regex can copy the line and be done,
// which is the entire difference between a report that is honest and one that
// is usable.
func renderAttestSuggestions(term *display.Terminal, res *attest.Result) {
	if len(res.Suggestions) == 0 {
		return
	}
	fmt.Println(display.Subheader(term, "This check is looser than it could be"))
	for _, s := range res.Suggestions {
		fmt.Printf("  %s\n", display.Muted(term, s.Why))
		fmt.Printf("    %s\n\n", display.Bold(term, suggestionCommand(res, s)))
	}
}

// suggestionCommand renders a suggestion as a runnable line.
//
// A suggestion carrying a whole Command names a different tool and is printed
// as-is; one carrying Flags is an argument to add to the command just run, so
// the run is reconstructed around it.
func suggestionCommand(res *attest.Result, s attest.Suggestion) string {
	if s.Command != "" {
		return s.Command
	}
	return fmt.Sprintf("vulnetix attest verify %s %s", res.Artifact, s.Flags)
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
	attestVerifyCmd.Flags().String("identity", "", "Require the signer to match this regular expression (the command prints the one it found)")
	attestVerifyCmd.Flags().String("issuer", "", "OIDC issuer the certificate must name")
	attestVerifyCmd.Flags().String("trusted-root", "",
		"Root certificate of a private Sigstore deployment (default: the built-in public-good root; also SIGSTORE_ROOT_FILE)")
	attestVerifyCmd.Flags().StringArray("require", nil,
		"Fail when this check did not run, e.g. transparency-log (repeatable)")
}
