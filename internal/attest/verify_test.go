package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// signingFixture is a self-signed certificate and key standing in for a Fulcio
// one, plus the CA that issued it.
type signingFixture struct {
	key      *ecdsa.PrivateKey
	certPEM  string
	rootPEM  string
	rootPath string
	dir      string
}

func newSigningFixture(t *testing.T, subject, issuer string) *signingFixture {
	t.Helper()
	dir := t.TempDir()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(subject)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "signer"},
		// Ten minutes, like Fulcio.
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(9 * time.Minute),
		URIs:        []*url.URL{uri},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Value: []byte(issuer),
		}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	f := &signingFixture{
		key:     leafKey,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		dir:     dir,
	}
	f.rootPath = filepath.Join(dir, "root.pem")
	if err := os.WriteFile(f.rootPath, []byte(f.rootPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// sign produces an ASN.1 DER ECDSA signature over the SHA-256 of data.
func (f *signingFixture) sign(t *testing.T, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// writeDSSE writes a DSSE envelope over a payload.
func (f *signingFixture) writeDSSE(t *testing.T, name string, payload []byte) string {
	t.Helper()
	const payloadType = "application/vnd.cyclonedx+json"
	sig := f.sign(t, dssePAE(payloadType, payload))

	env := map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"payloadType": payloadType,
		"signatures": []map[string]string{{
			"sig":  base64.StdEncoding.EncodeToString(sig),
			"cert": f.certPEM,
		}},
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeCosign writes a detached signature and certificate for an artefact.
func (f *signingFixture) writeCosign(t *testing.T, name string, artifact []byte) (artifactPath, sigPath, certPath string) {
	t.Helper()
	artifactPath = filepath.Join(f.dir, name)
	sigPath = artifactPath + ".sig"
	certPath = artifactPath + ".pem"

	sig := f.sign(t, artifact)
	for path, body := range map[string][]byte{
		artifactPath: artifact,
		sigPath:      []byte(base64.StdEncoding.EncodeToString(sig)),
		certPath:     []byte(f.certPEM),
	} {
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return artifactPath, sigPath, certPath
}

func checkNamed(res *Result, name string) *Check {
	for i := range res.Checks {
		if res.Checks[i].Name == name {
			return &res.Checks[i]
		}
	}
	return nil
}

func TestVerifyDSSE(t *testing.T) {
	f := newSigningFixture(t, "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main",
		"https://token.actions.githubusercontent.com")
	payload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)
	envelope := f.writeDSSE(t, "sbom.cdx.json.intoto.jsonl", payload)

	res, err := Verify(Options{ArtifactPath: "sbom.cdx.json", EnvelopePath: envelope, TrustedRootPath: f.rootPath})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified() {
		t.Fatalf("a valid DSSE envelope did not verify: %+v", res.Checks)
	}
	if c := checkNamed(res, "signature"); c == nil || c.Status != CheckPassed {
		t.Errorf("signature check = %+v", c)
	}
	if res.Identity.Subject == "" {
		t.Error("no subject extracted from the certificate")
	}
	if res.Identity.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("issuer = %q", res.Identity.Issuer)
	}
}

// TestVerifyDSSERejectsTamperedPayload is the property the whole package
// exists for.
func TestVerifyDSSERejectsTamperedPayload(t *testing.T) {
	f := newSigningFixture(t, "https://example.com/signer", "https://issuer.example.com")
	envelope := f.writeDSSE(t, "tampered.intoto.jsonl", []byte(`{"a":1}`))

	// Rewrite the payload, leaving the signature in place.
	data, err := os.ReadFile(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(`{"a":2}`))
	patched, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envelope, patched, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(Options{ArtifactPath: "tampered", EnvelopePath: envelope})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified() {
		t.Fatal("a tampered payload verified")
	}
	if c := checkNamed(res, "signature"); c == nil || c.Status != CheckFailed {
		t.Errorf("signature check = %+v, want failed", c)
	}
}

func TestVerifyCosignDetached(t *testing.T) {
	f := newSigningFixture(t, "https://example.com/signer", "https://issuer.example.com")
	artifact := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)
	path, sigPath, certPath := f.writeCosign(t, "sbom.cdx.json", artifact)

	res, err := Verify(Options{
		ArtifactPath: path, Artifact: artifact,
		SignaturePath: sigPath, CertificatePath: certPath,
		TrustedRootPath: f.rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified() {
		t.Fatalf("a valid detached signature did not verify: %+v", res.Checks)
	}

	// A different artefact under the same signature must fail.
	res, err = Verify(Options{
		ArtifactPath: path, Artifact: []byte(`{"different":true}`),
		SignaturePath: sigPath, CertificatePath: certPath,
		TrustedRootPath: f.rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified() {
		t.Fatal("a signature verified against the wrong artefact")
	}
}

// TestChainIsVerifiedByDefault pins the corrected default. Demanding a
// --trusted-root before doing any chain work made the user answer a question
// the tool can answer itself: cosign verifies against the public-good root
// without being asked, and so does this.
func TestChainIsVerifiedByDefault(t *testing.T) {
	f := newSigningFixture(t, "https://example.com/signer", "https://issuer.example.com")
	envelope := f.writeDSSE(t, "unrooted.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{ArtifactPath: "unrooted", EnvelopePath: envelope})
	if err != nil {
		t.Fatal(err)
	}
	c := checkNamed(res, "certificate-chain")
	if c == nil {
		t.Fatal("no certificate-chain check ran")
	}
	// The fixture CA is not Sigstore, so with no override this must FAIL —
	// not skip. A skip would mean the tool declined to have an opinion about a
	// certificate from an unknown authority.
	if c.Status != CheckFailed {
		t.Errorf("certificate-chain = %q, want failed for a certificate from an unknown CA", c.Status)
	}
	if !strings.Contains(c.Detail, "--trusted-root") {
		t.Errorf("the failure does not say how to fix it: %q", c.Detail)
	}
	if res.Verified() {
		t.Error("a certificate from an unknown CA was reported as verified")
	}
}

// TestEmbeddedRootIsUsable guards the pinned trust anchor itself. A root that
// failed to parse, or that had quietly expired, would make every default
// verification fail with an unhelpful chain error.
func TestEmbeddedRootIsUsable(t *testing.T) {
	anchor, err := PublicGood()
	if err != nil {
		t.Fatalf("the embedded Sigstore root does not parse: %v", err)
	}
	if len(anchor.Roots) == 0 {
		t.Fatal("the embedded anchor holds no certificates")
	}
	name, expiry := anchor.EarliestExpiry()
	if name == "" || expiry == "" {
		t.Fatal("the anchor reports no expiry")
	}
	for _, c := range anchor.Roots {
		if c.NotAfter.Before(time.Now()) {
			t.Errorf("embedded root %q expired on %s; refresh internal/attest/roots/",
				c.Subject.CommonName, c.NotAfter.Format("2006-01-02"))
		}
	}
}

// TestIdentityIsAFactNotASkippedCheck pins the second half of the fix. The
// identity is always read; not having an expectation to compare it against is
// not a gap in the verification, and listing it as "skipped" told a reader they
// had failed at something without saying at what.
func TestIdentityIsAFactNotASkippedCheck(t *testing.T) {
	subject := "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
	f := newSigningFixture(t, subject, "https://token.actions.githubusercontent.com")
	envelope := f.writeDSSE(t, "facts.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{
		ArtifactPath: "facts", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The identity is reported as a fact.
	if res.Identity.Subject != subject {
		t.Errorf("Identity.Subject = %q, want the certificate's SAN", res.Identity.Subject)
	}
	// And not as a check at all, since nothing was asked of it.
	for _, name := range []string{"identity", "issuer"} {
		if c := checkNamed(res, name); c != nil {
			t.Errorf("%s appears as a check (%q) when no expectation was given", name, c.Status)
		}
	}
	// Instead, a suggestion carrying the flag that would pin it — pre-filled,
	// so somebody who has never written one can paste it back.
	if len(res.Suggestions) == 0 {
		t.Fatal("no suggestions offered for an unpinned verification")
	}
	var sawIdentity bool
	for _, s := range res.Suggestions {
		if strings.Contains(s.Flags, "--identity") {
			sawIdentity = true
			if !strings.Contains(s.Flags, "acme/repo") {
				t.Errorf("the --identity suggestion is not pre-filled: %q", s.Flags)
			}
		}
		if s.Why == "" {
			t.Errorf("suggestion %q has no explanation", s.Flags)
		}
	}
	if !sawIdentity {
		t.Errorf("no --identity suggestion offered: %+v", res.Suggestions)
	}
}

// TestSuggestionsDisappearWhenPinned pins that the advice stops once taken.
func TestSuggestionsDisappearWhenPinned(t *testing.T) {
	subject := "https://example.com/signer"
	f := newSigningFixture(t, subject, "https://issuer.example.com")
	envelope := f.writeDSSE(t, "pinned.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{
		ArtifactPath: "pinned", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Identity: regexp.QuoteMeta(subject), Issuer: "https://issuer.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Suggestions {
		if strings.Contains(s.Flags, "--identity") || strings.Contains(s.Flags, "--issuer") {
			t.Errorf("still suggesting a pin that was already applied: %q", s.Flags)
		}
	}
	// The transparency-log suggestion remains: it is genuinely not done.
	if len(res.Suggestions) == 0 {
		t.Error("the transparency-log suggestion should survive, since it is still not checked")
	}
}

func TestChainVerifiesAgainstTrustedRoot(t *testing.T) {
	f := newSigningFixture(t, "https://example.com/signer", "https://issuer.example.com")
	envelope := f.writeDSSE(t, "rooted.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{
		ArtifactPath: "rooted", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := checkNamed(res, "certificate-chain"); c == nil || c.Status != CheckPassed {
		t.Errorf("certificate-chain = %+v, want passed", c)
	}

	// An unrelated root must not validate it.
	other := newSigningFixture(t, "https://example.com/other", "https://issuer.example.com")
	res, err = Verify(Options{
		ArtifactPath: "rooted", EnvelopePath: envelope, TrustedRootPath: other.rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := checkNamed(res, "certificate-chain"); c == nil || c.Status != CheckFailed {
		t.Errorf("certificate-chain = %+v, want failed against an unrelated root", c)
	}
	if res.Verified() {
		t.Error("a certificate that chains to nothing we trust was reported as verified")
	}
}

// TestRequireTurnsSkipIntoFailure is how a pipeline that genuinely needs chain
// validation gets told it did not happen.
func TestRequireTurnsSkipIntoFailure(t *testing.T) {
	f := newSigningFixture(t, "https://example.com/signer", "https://issuer.example.com")
	envelope := f.writeDSSE(t, "required.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{
		ArtifactPath: "required", EnvelopePath: envelope,
		Require: []string{"certificate-chain"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := checkNamed(res, "certificate-chain")
	if c == nil || c.Status != CheckFailed {
		t.Fatalf("certificate-chain = %+v, want failed when required and not performed", c)
	}
	if res.Verified() {
		t.Error("a required-but-skipped check did not fail verification")
	}
}

func TestIdentityAndIssuerChecks(t *testing.T) {
	subject := "https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main"
	f := newSigningFixture(t, subject, "https://token.actions.githubusercontent.com")
	envelope := f.writeDSSE(t, "identity.intoto.jsonl", []byte(`{}`))

	// Matching identity and issuer pass.
	res, err := Verify(Options{
		ArtifactPath: "identity", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Identity: `^https://github\.com/acme/.*`,
		Issuer:   "https://token.actions.githubusercontent.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified() {
		t.Fatalf("matching identity failed: %+v", res.Checks)
	}

	// A different org must fail.
	res, err = Verify(Options{
		ArtifactPath: "identity", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Identity: `^https://github\.com/someone-else/.*`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified() {
		t.Error("a signature from a different organisation verified")
	}

	// A wrong issuer must fail: accepting any provider Fulcio trusts would let
	// anyone with a Google account sign as this workflow.
	res, err = Verify(Options{
		ArtifactPath: "identity", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Issuer: "https://accounts.google.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified() {
		t.Error("a signature from a different OIDC issuer verified")
	}
}

// TestExpiredCertificatePasses covers the keyless lifetime. A Fulcio
// certificate lives ten minutes, so failing every signature older than that
// would make the verifier useless — the signature was valid when it was made.
func TestExpiredCertificatePasses(t *testing.T) {
	f := newSigningFixture(t, "https://example.com/signer", "https://issuer.example.com")
	envelope := f.writeDSSE(t, "old.intoto.jsonl", []byte(`{}`))

	res, err := Verify(Options{
		ArtifactPath: "old", EnvelopePath: envelope, TrustedRootPath: f.rootPath,
		Now: time.Now().Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := checkNamed(res, "certificate-validity")
	if c == nil || c.Status != CheckPassed {
		t.Fatalf("certificate-validity = %+v, want passed for an expired keyless cert", c)
	}
	// But it must say the caveat, or a reader would think the expiry was checked.
	if c.Detail == "" {
		t.Error("an expired certificate passed with no explanation of what that does and does not mean")
	}
	if !res.Verified() {
		t.Error("an old but valid signature did not verify")
	}
}

func TestVerifyNeedsSomethingToVerify(t *testing.T) {
	if _, err := Verify(Options{ArtifactPath: "x"}); err == nil {
		t.Error("Verify accepted no signature material")
	}
}
