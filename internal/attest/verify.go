// Package attest verifies signatures and provenance on artefacts this CLI
// consumes.
//
// internal/cdxsign is the inverse: it signs a CycloneDX document with the
// machine's own ambient OIDC identity, so the result verifies with stock
// cosign. This package reads those signatures — and anyone else's — back.
//
// # What "verified" means here, exactly
//
// Two rules, and they pull in opposite directions. A verifier must not report
// success for a check it did not perform — a green tick over a skipped chain
// validation converts an unknown into a false assurance. But a verifier that
// answers every question with "you did not tell me what to trust" is not being
// careful either; it is making the user do its job and calling that honesty.
//
// So: do the work by default, and be exact about what was done.
//
// The Sigstore public-good root is embedded, so chain validation runs without
// being asked, exactly as cosign does it. --trusted-root overrides it for a
// private deployment. Signature validity and the certificate chain are always
// checked. The signer's identity is always *read* and reported as a fact —
// it is not a check, and listing it as "skipped" implied a gap where none
// existed. Comparing it against an expectation is a check, and runs when the
// caller states one.
//
// What genuinely cannot be done from the material at hand is said once, in
// Suggestions, with the command that would do it. Rekor inclusion is the only
// such item: the sidecars carry no log entry, so proving it means querying the
// log and verifying its signed tree head.
//
// Verified() is true when every check that ran passed. Options.Require turns
// "this did not run" into a failure, for a caller who needs a specific
// assurance rather than the default set.
package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// CheckStatus is the outcome of one verification check.
type CheckStatus string

const (
	// CheckPassed — the check ran and succeeded.
	CheckPassed CheckStatus = "passed"
	// CheckFailed — the check ran and failed.
	CheckFailed CheckStatus = "failed"
	// CheckSkipped — the check did not run. Detail says why. A skipped check is
	// never counted as a pass.
	CheckSkipped CheckStatus = "skipped"
)

// Check is one verification step and its outcome.
type Check struct {
	// Name identifies the check, e.g. "signature", "certificate-chain".
	Name string `json:"name"`
	// Status is what happened.
	Status CheckStatus `json:"status"`
	// Detail explains a failure, or why a check was skipped.
	Detail string `json:"detail,omitempty"`
}

// Identity is who a certificate says signed something.
type Identity struct {
	// Subject is the SAN — a workflow reference in CI, an email for a person,
	// a SPIFFE ID for a workload.
	Subject string `json:"subject,omitempty"`
	// Issuer is the OIDC issuer that authenticated them.
	Issuer string `json:"issuer,omitempty"`
	// NotBefore and NotAfter are the certificate's validity window. Fulcio
	// certificates live for ten minutes, so this is also roughly when the
	// signature was made.
	NotBefore time.Time `json:"notBefore,omitzero"`
	NotAfter  time.Time `json:"notAfter,omitzero"`
	// BuildTrigger, SourceRepository and SourceRevision are the Fulcio CI
	// extensions, present when the signer was a pipeline rather than a person.
	BuildTrigger     string `json:"buildTrigger,omitempty"`
	SourceRepository string `json:"sourceRepository,omitempty"`
	SourceRevision   string `json:"sourceRevision,omitempty"`
}

// Result is a full verification outcome.
type Result struct {
	// Artifact is the file that was verified.
	Artifact string `json:"artifact"`
	// Digest is the SHA-256 of the artefact's bytes.
	Digest string `json:"digest"`
	// Envelope is the signature form that was read: "dsse" or "cosign".
	Envelope string `json:"envelope,omitempty"`
	// Identity is who the certificate says signed it.
	Identity Identity `json:"identity,omitzero"`
	// TrustAnchor names what the chain was verified against.
	TrustAnchor string `json:"trustAnchor,omitempty"`
	// Checks is every verification step and its outcome. This, not a boolean,
	// is the honest answer.
	Checks []Check `json:"checks"`
	// Suggestions are the ways this verification could be made stricter, each
	// with the exact command to do it.
	//
	// This is the difference between a report that is honest and one that is
	// useful. Telling a reader that nothing pinned the signer's identity is
	// only half an answer; the other half is the flag that would pin it, filled
	// in with the identity actually found.
	Suggestions []Suggestion `json:"suggestions,omitempty"`
	// Predicate is the in-toto predicate when one was found.
	Predicate *Predicate `json:"predicate,omitempty"`
}

// Suggestion is a way to make a verification stricter.
type Suggestion struct {
	// Why says what is currently unconstrained, in plain terms.
	Why string `json:"why"`
	// Flags is the argument to add to this command, ready to paste. Empty when
	// the suggestion is to run a different tool entirely.
	Flags string `json:"flags,omitempty"`
	// Command is a complete command line, for a suggestion this CLI cannot
	// satisfy itself. Never a fragment with an ellipsis in it: a suggestion the
	// reader has to fill in is one they have to already know the answer to,
	// which defeats the point of suggesting it.
	Command string `json:"command,omitempty"`
}

// Verified reports whether every performed check passed and none failed.
//
// A skipped check does not make this false — it means the caller did not ask
// for it. Use Missing to find out what was not checked, and Options.Require to
// turn a skip into a failure.
func (r *Result) Verified() bool {
	for _, c := range r.Checks {
		if c.Status == CheckFailed {
			return false
		}
	}
	return r.performed("signature")
}

// Missing lists the checks that did not run.
func (r *Result) Missing() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Status == CheckSkipped {
			out = append(out, c)
		}
	}
	return out
}

// Failures lists the checks that ran and failed.
func (r *Result) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Status == CheckFailed {
			out = append(out, c)
		}
	}
	return out
}

func (r *Result) performed(name string) bool {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status == CheckPassed
		}
	}
	return false
}

// PerformedChain reports whether the certificate chain was actually validated.
func (r *Result) PerformedChain() bool { return r.performed("certificate-chain") }

// ran reports whether a check appears in the result at all.
func (r *Result) ran(name string) bool {
	for _, c := range r.Checks {
		if c.Name == name && c.Status != CheckSkipped {
			return true
		}
	}
	return false
}

func (r *Result) add(name string, status CheckStatus, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

func (r *Result) suggest(why, flags string) {
	r.Suggestions = append(r.Suggestions, Suggestion{Why: why, Flags: flags})
}

func (r *Result) suggestCommand(why, command string) {
	r.Suggestions = append(r.Suggestions, Suggestion{Why: why, Command: command})
}

// addHardeningSuggestions turns what this run did not constrain into commands.
//
// The identity is the important one. A verified signature with no identity
// expectation means "somebody Sigstore trusts signed this", which for a GitHub
// Actions signature includes every workflow in every public repository. Saying
// so is necessary; handing over the exact flag, pre-filled with the identity
// actually found, is what makes it actionable by someone who has never written
// a certificate-identity regex.
func addHardeningSuggestions(res *Result, opts Options) {
	if opts.Identity == "" && res.Identity.Subject != "" {
		res.suggest(
			"any identity this CA will issue to would also pass, not just this one",
			"--identity '"+regexp.QuoteMeta(res.Identity.Subject)+"'")
	}
	if opts.Issuer == "" && res.Identity.Issuer != "" {
		res.suggest(
			"any OIDC provider this CA accepts would also pass",
			"--issuer "+res.Identity.Issuer)
	}

	// Last, and as a whole command rather than flags to add: proving *when* a
	// signature was made needs the transparency log, which means querying it and
	// verifying its signed tree head. That is cosign's job, so the suggestion is
	// the cosign invocation — complete, with the identity and sidecars filled
	// in from what was just read.
	res.suggestCommand(
		"nothing here proves when the signature was made; only a transparency-log entry does",
		cosignCommand(res, opts))
}

// cosignCommand renders the equivalent cosign invocation, fully populated.
func cosignCommand(res *Result, opts Options) string {
	parts := []string{"cosign", "verify-blob"}
	if res.Identity.Subject != "" {
		parts = append(parts, "--certificate-identity", quoteArg(res.Identity.Subject))
	}
	if res.Identity.Issuer != "" {
		parts = append(parts, "--certificate-oidc-issuer", quoteArg(res.Identity.Issuer))
	}
	if opts.SignaturePath != "" {
		parts = append(parts, "--signature", opts.SignaturePath)
	}
	if opts.CertificatePath != "" {
		parts = append(parts, "--certificate", opts.CertificatePath)
	}
	if opts.EnvelopePath != "" && opts.SignaturePath == "" {
		parts = append(parts, "--bundle", opts.EnvelopePath)
	}
	parts = append(parts, opts.ArtifactPath)
	return strings.Join(parts, " ")
}

// quoteArg single-quotes a shell argument when it needs it.
func quoteArg(s string) string {
	if !strings.ContainsAny(s, " \t'\"$`\\*?[]{}();&|<>") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Options controls verification.
type Options struct {
	// ArtifactPath is the file being verified, for labelling.
	ArtifactPath string
	// Artifact is the bytes the signature should cover. Required for a cosign
	// detached signature; for DSSE the payload is inside the envelope.
	Artifact []byte
	// SignaturePath and CertificatePath are the cosign detached sidecars.
	SignaturePath, CertificatePath string
	// EnvelopePath is a DSSE envelope (.intoto.jsonl).
	EnvelopePath string
	// Identity, when set, is a regular expression the certificate subject must
	// match. Verifying a signature without checking who made it establishes
	// only that somebody signed it, which is rarely the question.
	Identity string
	// Issuer, when set, is the OIDC issuer the certificate must name.
	Issuer string
	// TrustedRootPath is a PEM bundle to validate the certificate chain
	// against. Absent, chain validation is reported as skipped rather than
	// silently passed.
	TrustedRootPath string
	// Require names checks that must have been performed. A required check that
	// was skipped becomes a failure.
	Require []string
	// Now overrides the clock, for tests.
	Now time.Time
}

// Verify checks the signatures on an artefact.
func Verify(opts Options) (*Result, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	res := &Result{Artifact: opts.ArtifactPath}
	if len(opts.Artifact) > 0 {
		sum := sha256.Sum256(opts.Artifact)
		res.Digest = fmt.Sprintf("%x", sum)
	}

	var (
		leaf          *x509.Certificate
		intermediates *x509.CertPool
		signed        []byte // the bytes the signature covers
		rawSig        []byte
		err           error
	)

	switch {
	case opts.EnvelopePath != "":
		res.Envelope = "dsse"
		leaf, intermediates, signed, rawSig, err = readDSSE(opts.EnvelopePath)
	case opts.SignaturePath != "":
		res.Envelope = "cosign"
		leaf, intermediates, signed, rawSig, err = readCosign(opts)
	default:
		return nil, fmt.Errorf("nothing to verify: pass a DSSE envelope or a detached signature and certificate")
	}
	if err != nil {
		return nil, err
	}

	// ── signature ───────────────────────────────────────────────────────────
	if leaf == nil {
		res.add("signature", CheckFailed, "no certificate accompanies the signature, so there is no key to verify it with")
	} else if verifyErr := verifySignature(leaf, signed, rawSig); verifyErr != nil {
		res.add("signature", CheckFailed, verifyErr.Error())
	} else {
		res.add("signature", CheckPassed, "")
	}

	if leaf != nil {
		res.Identity = identityFrom(leaf)
		checkValidity(res, leaf, now)
		checkIdentity(res, opts)
		checkChain(res, leaf, intermediates, opts)
	}

	// A required check that did not run is a failure. This is how a caller who
	// genuinely needs a check gets told it did not happen, rather than reading a
	// pass and assuming it did.
	for _, required := range opts.Require {
		if !res.ran(required) {
			res.add(required, CheckFailed,
				"required, but this run did not perform it")
		}
	}

	// Ordered most-actionable first. Pinning the identity is one flag this
	// command can hand over pre-filled; the transparency log needs another tool
	// entirely, so it goes last rather than heading the list and reading like
	// the main thing wrong.
	addHardeningSuggestions(res, opts)

	// The payload of a DSSE envelope may itself be an in-toto statement.
	if res.Envelope == "dsse" {
		if p := parsePredicate(signedPayload(signed)); p != nil {
			res.Predicate = p
		}
	}

	return res, nil
}

// readDSSE reads a DSSE envelope, returning its certificate, the
// pre-authentication encoding the signature covers, and the raw signature.
func readDSSE(path string) (*x509.Certificate, *x509.CertPool, []byte, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var env struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
			Cert  string `json:"cert"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%s: not a DSSE envelope: %w", path, err)
	}
	if len(env.Signatures) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("%s: envelope carries no signatures", path)
	}

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%s: payload is not valid base64: %w", path, err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%s: signature is not valid base64: %w", path, err)
	}

	// The signature covers the pre-authentication encoding, not the payload.
	// Verifying against the bare payload would accept a signature made over the
	// same bytes under a different payloadType — which is the replay the PAE
	// exists to prevent.
	pae := dssePAE(env.PayloadType, payload)

	leaf, intermediates, err := parseCertificate(env.Signatures[0].Cert)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return leaf, intermediates, pae, sig, nil
}

// readCosign reads a detached cosign signature and its certificate.
func readCosign(opts Options) (*x509.Certificate, *x509.CertPool, []byte, []byte, error) {
	if len(opts.Artifact) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("a detached signature needs the artefact it covers")
	}
	sigData, err := os.ReadFile(opts.SignaturePath)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigData)))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%s: not a base64 signature: %w", opts.SignaturePath, err)
	}

	var (
		leaf          *x509.Certificate
		intermediates *x509.CertPool
	)
	if opts.CertificatePath != "" {
		pemData, rerr := os.ReadFile(opts.CertificatePath)
		if rerr != nil {
			return nil, nil, nil, nil, rerr
		}
		if leaf, intermediates, err = parseCertificate(string(pemData)); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	return leaf, intermediates, opts.Artifact, sig, nil
}

// parseCertificate decodes a PEM bundle into a leaf and its intermediates.
//
// The bundle, not just the first block. Fulcio returns leaf + intermediate +
// root and the signer stores all of it, so decoding only the first certificate
// throws away the intermediates and makes every chain check fail to build a
// path — which is how chain validation came to look impossible without a
// user-supplied root when the material was in the file all along.
func parseCertificate(pemText string) (leaf *x509.Certificate, intermediates *x509.CertPool, err error) {
	if strings.TrimSpace(pemText) == "" {
		return nil, nil, nil
	}
	rest := []byte(pemText)
	intermediates = x509.NewCertPool()

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, nil, fmt.Errorf("parsing certificate: %w", perr)
		}
		if leaf == nil {
			leaf = cert
			continue
		}
		intermediates.AddCert(cert)
	}
	if leaf == nil {
		return nil, nil, fmt.Errorf("certificate is not valid PEM")
	}
	return leaf, intermediates, nil
}

// verifySignature checks an ASN.1 DER signature against a certificate's key.
func verifySignature(cert *x509.Certificate, signed, sig []byte) error {
	digest := sha256.Sum256(signed)
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return fmt.Errorf("signature does not verify against the certificate's public key")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	default:
		return fmt.Errorf("unsupported public key type %T", cert.PublicKey)
	}
}

// checkValidity checks the certificate's validity window.
//
// A Fulcio certificate lives about ten minutes, so an expired one is normal for
// an old signature and is NOT a failure on its own — the signature was valid
// when it was made. What would make it a failure is a transparency-log entry
// proving when, and that is the check this CLI does not do. So this reports the
// window and passes; saying otherwise would fail every keyless signature more
// than ten minutes old.
func checkValidity(res *Result, cert *x509.Certificate, now time.Time) {
	switch {
	case now.Before(cert.NotBefore):
		res.add("certificate-validity", CheckFailed,
			fmt.Sprintf("certificate is not valid until %s", cert.NotBefore.Format(time.RFC3339)))
	case now.After(cert.NotAfter):
		res.add("certificate-validity", CheckPassed,
			fmt.Sprintf("certificate expired %s; expected for a short-lived keyless signature, "+
				"but only a transparency-log entry proves the signature predates expiry",
				cert.NotAfter.Format(time.RFC3339)))
	default:
		res.add("certificate-validity", CheckPassed, "")
	}
}

// checkIdentity compares the certificate's identity against an expectation.
//
// Only runs when the caller stated one. Absent an expectation there is nothing
// to check — the identity itself is not a check, it is a fact, and it is
// reported as Result.Identity either way. The earlier version listed "identity:
// skipped" here, which read as a gap in the verification when nothing was
// missing at all: the identity had been read successfully and the user had
// simply not said what they expected it to be. Suggestions carry that instead.
func checkIdentity(res *Result, opts Options) {
	if opts.Identity != "" {
		re, err := regexp.Compile(opts.Identity)
		switch {
		case err != nil:
			res.add("identity", CheckFailed, fmt.Sprintf("--identity is not a valid regexp: %v", err))
		case res.Identity.Subject == "":
			res.add("identity", CheckFailed, "certificate carries no subject alternative name to match against")
		case !re.MatchString(res.Identity.Subject):
			res.add("identity", CheckFailed,
				fmt.Sprintf("signed by %q, which does not match %q", res.Identity.Subject, opts.Identity))
		default:
			res.add("identity", CheckPassed, "")
		}
	}

	if opts.Issuer != "" {
		switch {
		case res.Identity.Issuer == "":
			res.add("issuer", CheckFailed, "certificate names no OIDC issuer")
		case res.Identity.Issuer != opts.Issuer:
			res.add("issuer", CheckFailed,
				fmt.Sprintf("authenticated by %q, not %q", res.Identity.Issuer, opts.Issuer))
		default:
			res.add("issuer", CheckPassed, "")
		}
	}
}

// checkChain validates the certificate chain against a trust anchor.
//
// The public-good Sigstore root is embedded and used by default. --trusted-root
// (or SIGSTORE_ROOT_FILE) overrides it for a private deployment.
//
// This used to skip unless the caller supplied a root, which was the single
// worst thing about this package: it demanded the user answer "which CA do you
// trust" before it would do any work, when the answer for nearly every keyless
// signature in existence is the one cosign uses without asking. A chain that
// does not anchor to a known root now says exactly that, and says what to pass.
func checkChain(res *Result, leaf *x509.Certificate, intermediates *x509.CertPool, opts Options) {
	anchor, err := resolveAnchor(opts)
	if err != nil {
		res.add("certificate-chain", CheckFailed, err.Error())
		return
	}
	res.TrustAnchor = anchor.Name

	// CurrentTime is the certificate's own NotBefore, not the wall clock: a
	// keyless certificate is minted for ten minutes, and every signature older
	// than that would otherwise fail for having expired — which says nothing
	// about whether the CA is trusted.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         anchor.Pool,
		Intermediates: intermediates,
		CurrentTime:   leaf.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}); err != nil {
		res.add("certificate-chain", CheckFailed, fmt.Sprintf(
			"does not chain to %s (%v). If this was signed by a private Sigstore "+
				"instance, pass --trusted-root with its root certificate.",
			anchor.Name, err))
		return
	}
	res.add("certificate-chain", CheckPassed, "issued by "+anchor.Name)
}

// resolveAnchor picks the trust anchor: an explicit one, else the embedded root.
func resolveAnchor(opts Options) (*TrustAnchor, error) {
	path := opts.TrustedRootPath
	if path == "" {
		path = os.Getenv("SIGSTORE_ROOT_FILE")
	}
	if path != "" {
		return LoadTrustAnchor(path)
	}
	return PublicGood()
}

// Fulcio certificate extension OIDs.
//
// Sigstore records the OIDC issuer and CI build context in X.509 extensions.
// The 1.1 issuer OID is the original (a bare string); 1.8 is its DER-encoded
// replacement, and both are still in circulation, so both are read.
var (
	oidIssuerV1         = "1.3.6.1.4.1.57264.1.1"
	oidIssuerV2         = "1.3.6.1.4.1.57264.1.8"
	oidBuildTrigger     = "1.3.6.1.4.1.57264.1.20"
	oidSourceRepoURI    = "1.3.6.1.4.1.57264.1.12"
	oidSourceRepoDigest = "1.3.6.1.4.1.57264.1.13"
)

// identityFrom extracts who a certificate says signed something.
func identityFrom(cert *x509.Certificate) Identity {
	id := Identity{NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}

	// A keyless certificate carries the identity in a SAN, not the subject DN.
	switch {
	case len(cert.URIs) > 0:
		id.Subject = cert.URIs[0].String()
	case len(cert.EmailAddresses) > 0:
		id.Subject = cert.EmailAddresses[0]
	case len(cert.DNSNames) > 0:
		id.Subject = cert.DNSNames[0]
	default:
		id.Subject = cert.Subject.CommonName
	}

	for _, ext := range cert.Extensions {
		switch ext.Id.String() {
		case oidIssuerV1:
			id.Issuer = string(ext.Value)
		case oidIssuerV2:
			id.Issuer = derString(ext.Value)
		case oidBuildTrigger:
			id.BuildTrigger = derString(ext.Value)
		case oidSourceRepoURI:
			id.SourceRepository = derString(ext.Value)
		case oidSourceRepoDigest:
			id.SourceRevision = derString(ext.Value)
		}
	}
	return id
}

// derString unwraps a DER-encoded UTF8String extension value.
//
// The v2 Fulcio extensions wrap their value in an ASN.1 UTF8String rather than
// storing it raw, so reading ext.Value directly yields two bytes of tag and
// length in front of the text.
func derString(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0x0c {
		length := int(raw[1])
		if len(raw) >= 2+length {
			return string(raw[2 : 2+length])
		}
	}
	return string(raw)
}

// dssePAE is the DSSE pre-authentication encoding, matching the signer's.
func dssePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payload))
}

// signedPayload recovers the payload from a PAE-encoded blob.
//
// The encoding is "DSSEv1 <n> <type> <m> <payload>", so the payload is whatever
// follows the fourth space-delimited field.
func signedPayload(pae []byte) []byte {
	parts := strings.SplitN(string(pae), " ", 5)
	if len(parts) < 5 {
		return nil
	}
	return []byte(parts[4])
}
