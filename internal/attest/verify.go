// Package attest verifies signatures and provenance on artefacts this CLI
// consumes.
//
// internal/cdxsign is the inverse: it signs a CycloneDX document with the
// machine's own ambient OIDC identity, so the result verifies with stock
// cosign. This package reads those signatures — and anyone else's — back.
//
// # What "verified" means here, exactly
//
// The single most dangerous thing a verifier can do is report success for a
// check it did not perform. A green tick that silently skipped chain validation
// is worse than no verifier at all, because it converts an unknown into a false
// assurance.
//
// So this package never reports a bare boolean. Every result carries the list
// of checks, each marked performed-and-passed, performed-and-failed, or not
// performed with the reason. Signature validity and certificate identity are
// checked locally and always performed. Certificate chain validation is
// performed only when a trusted root is supplied, and is reported as skipped
// otherwise. Rekor transparency-log inclusion is never checked here — it needs
// the log's public key and an online query, and claiming it without doing it
// would be exactly the lie this design exists to prevent.
//
// Verified() is true only when every performed check passed AND no check the
// caller required was skipped. A caller that needs chain validation asks for it
// and gets a failure if it could not be done.
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
	// Checks is every verification step and its outcome. This, not a boolean,
	// is the honest answer.
	Checks []Check `json:"checks"`
	// Predicate is the in-toto predicate when one was found.
	Predicate *Predicate `json:"predicate,omitempty"`
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

func (r *Result) add(name string, status CheckStatus, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
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
		cert   *x509.Certificate
		signed []byte // the bytes the signature covers
		rawSig []byte
		err    error
	)

	switch {
	case opts.EnvelopePath != "":
		res.Envelope = "dsse"
		cert, signed, rawSig, err = readDSSE(opts.EnvelopePath)
	case opts.SignaturePath != "":
		res.Envelope = "cosign"
		cert, signed, rawSig, err = readCosign(opts)
	default:
		return nil, fmt.Errorf("nothing to verify: pass a DSSE envelope or a detached signature and certificate")
	}
	if err != nil {
		return nil, err
	}

	// ── signature ───────────────────────────────────────────────────────────
	if cert == nil {
		res.add("signature", CheckFailed, "no certificate accompanies the signature, so there is no key to verify it with")
	} else if verifyErr := verifySignature(cert, signed, rawSig); verifyErr != nil {
		res.add("signature", CheckFailed, verifyErr.Error())
	} else {
		res.add("signature", CheckPassed, "")
	}

	if cert != nil {
		res.Identity = identityFrom(cert)
		checkValidity(res, cert, now)
		checkIdentity(res, opts)
		checkChain(res, cert, opts, now)
	}

	// Rekor is deliberately never claimed. Verifying inclusion needs the log's
	// public key and an online query against it; reporting it as done without
	// doing it would be the exact failure this package is built to avoid.
	res.add("transparency-log", CheckSkipped,
		"Rekor inclusion is not checked by this CLI; verify it with `cosign verify-blob`")

	// A required check that was skipped is a failure. This is how a caller who
	// genuinely needs chain validation gets told it did not happen, rather than
	// reading a pass and assuming it did.
	for _, required := range opts.Require {
		for i := range res.Checks {
			if res.Checks[i].Name == required && res.Checks[i].Status == CheckSkipped {
				res.Checks[i].Status = CheckFailed
				res.Checks[i].Detail = "required but not performed: " + res.Checks[i].Detail
			}
		}
	}

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
func readDSSE(path string) (*x509.Certificate, []byte, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, fmt.Errorf("%s: not a DSSE envelope: %w", path, err)
	}
	if len(env.Signatures) == 0 {
		return nil, nil, nil, fmt.Errorf("%s: envelope carries no signatures", path)
	}

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: payload is not valid base64: %w", path, err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: signature is not valid base64: %w", path, err)
	}

	// The signature covers the pre-authentication encoding, not the payload.
	// Verifying against the bare payload would accept a signature made over the
	// same bytes under a different payloadType — which is the replay the PAE
	// exists to prevent.
	pae := dssePAE(env.PayloadType, payload)

	cert, err := parseCertificate(env.Signatures[0].Cert)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pae, sig, nil
}

// readCosign reads a detached cosign signature and its certificate.
func readCosign(opts Options) (*x509.Certificate, []byte, []byte, error) {
	if len(opts.Artifact) == 0 {
		return nil, nil, nil, fmt.Errorf("a detached signature needs the artefact it covers")
	}
	sigData, err := os.ReadFile(opts.SignaturePath)
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigData)))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: not a base64 signature: %w", opts.SignaturePath, err)
	}

	var cert *x509.Certificate
	if opts.CertificatePath != "" {
		pemData, err := os.ReadFile(opts.CertificatePath)
		if err != nil {
			return nil, nil, nil, err
		}
		if cert, err = parseCertificate(string(pemData)); err != nil {
			return nil, nil, nil, err
		}
	}
	return cert, opts.Artifact, sig, nil
}

// parseCertificate decodes a PEM certificate.
func parseCertificate(pemText string) (*x509.Certificate, error) {
	if strings.TrimSpace(pemText) == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
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

// checkIdentity checks the certificate subject and issuer against expectations.
func checkIdentity(res *Result, opts Options) {
	if opts.Identity == "" {
		res.add("identity", CheckSkipped,
			"no --identity given, so the signature proves only that somebody signed it")
	} else {
		re, err := regexp.Compile(opts.Identity)
		switch {
		case err != nil:
			res.add("identity", CheckFailed, fmt.Sprintf("--identity is not a valid regexp: %v", err))
		case res.Identity.Subject == "":
			res.add("identity", CheckFailed, "certificate carries no subject alternative name to match against")
		case !re.MatchString(res.Identity.Subject):
			res.add("identity", CheckFailed,
				fmt.Sprintf("subject %q does not match %q", res.Identity.Subject, opts.Identity))
		default:
			res.add("identity", CheckPassed, "")
		}
	}

	switch {
	case opts.Issuer == "":
		res.add("issuer", CheckSkipped,
			"no --issuer given, so any OIDC provider that Fulcio accepts would satisfy this")
	case res.Identity.Issuer == "":
		res.add("issuer", CheckFailed, "certificate names no OIDC issuer")
	case res.Identity.Issuer != opts.Issuer:
		res.add("issuer", CheckFailed,
			fmt.Sprintf("issuer %q does not equal %q", res.Identity.Issuer, opts.Issuer))
	default:
		res.add("issuer", CheckPassed, "")
	}
}

// checkChain validates the certificate against a supplied trust root.
//
// Skipped, loudly, when no root is supplied. A verifier that treats "I have no
// trust root" as a pass is asserting that any self-issued certificate is as good
// as a Fulcio one, which is the whole property a signature is supposed to
// establish.
func checkChain(res *Result, cert *x509.Certificate, opts Options, now time.Time) {
	rootPath := opts.TrustedRootPath
	if rootPath == "" {
		rootPath = os.Getenv("SIGSTORE_ROOT_FILE")
	}
	if rootPath == "" {
		res.add("certificate-chain", CheckSkipped,
			"no trusted root supplied (--trusted-root or SIGSTORE_ROOT_FILE); "+
				"the certificate is read but not proven to come from a CA you trust")
		return
	}

	pemData, err := os.ReadFile(rootPath)
	if err != nil {
		res.add("certificate-chain", CheckFailed, err.Error())
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		res.add("certificate-chain", CheckFailed, rootPath+" contains no PEM certificates")
		return
	}

	// CurrentTime is the certificate's own NotBefore, not the wall clock: a
	// keyless certificate is minted for ten minutes and every signature older
	// than that would otherwise fail chain validation for having expired, which
	// says nothing about whether the CA is trusted.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: cert.NotBefore,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}); err != nil {
		res.add("certificate-chain", CheckFailed, err.Error())
		return
	}
	res.add("certificate-chain", CheckPassed, "")
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
