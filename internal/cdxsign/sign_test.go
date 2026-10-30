package cdxsign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
)

// The Fulcio exchange itself is covered in vdb-cyclonedx, against a stand-in
// that verifies the proof of possession the way Fulcio does. What matters here
// is the behaviour a customer sees: an unsigned document is a normal outcome,
// not a failure, and nothing is written that pretends otherwise. When signing
// does succeed, every sidecar it promises has to exist and be usable, which is
// what the success-path test below checks.

// testIdentityToken is a JWT whose sub claim names the workload that ran the
// scan. Nothing here verifies its signature: that is Fulcio's job, and the stub
// below stands in for Fulcio.
const testIdentityToken = "eyJhbGciOiJSUzI1NiJ9." +
	"eyJzdWIiOiJzcGlmZmU6Ly9zaWdzdG9yZS52dWxuZXRpeC5jb20vY29kZS1zY2FubmVyIn0.sig"

// testSpiffeID is that sub claim, and so the identity a certificate issued for
// this token must carry.
const testSpiffeID = "spiffe://sigstore.vulnetix.com/code-scanner"

// testRekorUUID is the entry uuid the Rekor stub answers with.
const testRekorUUID = "0123456789abcdef0123456789abcdef"

func TestNoIdentityLeavesTheDocumentUnchanged(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.cdx.json")
	document := []byte(`{"bomFormat":"CycloneDX"}`)

	result, err := SignDocument(context.Background(), path, document)
	if err != nil {
		// A laptop has no OIDC identity. Failing here would mean discarding a
		// scan that completed successfully.
		t.Fatalf("SignDocument: %v", err)
	}
	if result.Signed() {
		t.Fatal("reported a signature with no identity to sign as")
	}
	if result.Skipped == "" {
		t.Fatal("skipped without saying why")
	}
	if string(result.Document) != string(document) {
		t.Fatal("the document changed even though nothing was signed")
	}

	// No sidecar may exist. A stale or empty .sig beside an unsigned document
	// is worse than no file: it reads as a signature that fails to verify.
	for _, suffix := range []string{".sig", ".pem", ".intoto.jsonl"} {
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("%s was written for an unsigned document", path+suffix)
		}
	}
}

func TestAnUnreachableCAIsReportedAndNothingIsWritten(t *testing.T) {
	// A token that exists, pointed at a CA that does not answer. This is the
	// case that must not silently produce a half-signed output directory.
	t.Setenv("SIGSTORE_ID_TOKEN", testIdentityToken)
	t.Setenv("SIGSTORE_FULCIO_URL", "http://127.0.0.1:1")
	t.Setenv("SIGSTORE_REKOR_URL", "-")

	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.cdx.json")
	document := []byte(`{"bomFormat":"CycloneDX"}`)

	result, err := SignDocument(context.Background(), path, document)
	if err == nil {
		t.Fatal("an unreachable CA produced no error")
	}
	if string(result.Document) != string(document) {
		t.Fatal("the returned document is not the one that must be written")
	}
	for _, suffix := range []string{".sig", ".pem", ".intoto.jsonl"} {
		if _, statErr := os.Stat(path + suffix); !os.IsNotExist(statErr) {
			t.Fatalf("%s was written despite the failure", path+suffix)
		}
	}
}

// The success path. A signed identity and a reachable CA produce the three
// detached sidecars beside the document, each checked for what its consumer
// needs rather than merely for existence.
func TestSigningWithAnAmbientIdentityWritesEverySidecar(t *testing.T) {
	fulcio := newFulcioStub(t)
	rekor := newRekorStub(t, 7)

	t.Setenv("SIGSTORE_ID_TOKEN", testIdentityToken)
	t.Setenv("SIGSTORE_FULCIO_URL", fulcio.URL)
	t.Setenv("SIGSTORE_REKOR_URL", rekor.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	dir := t.TempDir()
	// "reports" does not exist yet, so writing the sidecars has to create it.
	path := filepath.Join(dir, "reports", "sbom.cdx.json")
	document := []byte(`{"bomFormat":"CycloneDX"}`)

	result, err := SignDocument(context.Background(), path, document)
	if err != nil {
		t.Fatalf("SignDocument: %v", err)
	}
	if !result.Signed() {
		t.Fatalf("reported no signature after a successful signing: Skipped = %q", result.Skipped)
	}

	// JSF is embedded in the document, so the bytes to publish differ from the
	// bytes that were passed in. A caller that wrote its input instead would
	// publish bytes no sidecar covers.
	if string(result.Document) == string(document) {
		t.Fatal("the returned document is the input, so no JSF signature was embedded")
	}
	var embedded struct {
		Signature *struct {
			Algorithm string `json:"algorithm"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(result.Document, &embedded); err != nil {
		t.Fatalf("decode signed document: %v", err)
	}
	if embedded.Signature == nil {
		t.Fatal("the signed document carries no signature property")
	}

	// The identity and log entry come from the first signature in the list.
	// Rekor's stub counts up per call, so index 7 is the JSF signature's entry
	// and nothing else would produce this exact value.
	if result.Identity != testSpiffeID {
		t.Fatalf("Identity = %q, want the certificate subject %q", result.Identity, testSpiffeID)
	}
	if result.TlogEntryID != "7:"+testRekorUUID {
		t.Fatalf("TlogEntryID = %q, want %q", result.TlogEntryID, "7:"+testRekorUUID)
	}

	// Exactly the three sidecars the release workflows publish, and no others.
	want := map[string]bool{
		path + ".sig":          true,
		path + ".pem":          true,
		path + ".intoto.jsonl": true,
	}
	if len(result.Files) != len(want) {
		t.Fatalf("Files = %q, want the three sidecars", result.Files)
	}
	for _, f := range result.Files {
		if !want[f] {
			t.Fatalf("Files contains %q, which is not a sidecar name", f)
		}
		delete(want, f)
	}
	if len(want) != 0 {
		t.Fatalf("sidecars missing from Files: %v", want)
	}

	// The .pem sidecar is the certificate binding the signature to an identity.
	pemBytes, err := os.ReadFile(path + ".pem")
	if err != nil {
		t.Fatalf("read certificate sidecar: %v", err)
	}
	leafBlock, _ := pem.Decode(pemBytes)
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" {
		t.Fatalf("%s is not a PEM certificate", path+".pem")
	}
	cert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse certificate sidecar: %v", err)
	}
	if len(cert.URIs) == 0 || cert.URIs[0].String() != testSpiffeID {
		t.Fatalf("certificate identity = %v, want %q", cert.URIs, testSpiffeID)
	}

	// cosign verify-blob checks .sig against the blob the consumer downloaded,
	// which is the returned document.
	sigBytes, err := os.ReadFile(path + ".sig")
	if err != nil {
		t.Fatalf("read signature sidecar: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(string(sigBytes))
	if err != nil {
		t.Fatalf("%s is not base64: %v", path+".sig", err)
	}
	leafKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want ECDSA", cert.PublicKey)
	}
	digest := sha256.Sum256(result.Document)
	if !ecdsa.VerifyASN1(leafKey, digest[:], der) {
		t.Fatal("the .sig sidecar does not verify against the returned document")
	}
	unsignedDigest := sha256.Sum256(document)
	if ecdsa.VerifyASN1(leafKey, unsignedDigest[:], der) {
		t.Fatal("the .sig sidecar covers the input bytes, which are not published")
	}

	// The DSSE sidecar states its type and carries the published bytes.
	dsseBytes, err := os.ReadFile(path + ".intoto.jsonl")
	if err != nil {
		t.Fatalf("read DSSE sidecar: %v", err)
	}
	var envelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal(dsseBytes, &envelope); err != nil {
		t.Fatalf("decode DSSE sidecar: %v", err)
	}
	if envelope.PayloadType != cyclonedx.DSSEPayloadType {
		t.Fatalf("payloadType = %q, want %q", envelope.PayloadType, cyclonedx.DSSEPayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode DSSE payload: %v", err)
	}
	if string(payload) != string(result.Document) {
		t.Fatal("the DSSE envelope does not carry the returned document")
	}

	// The sidecars are ordinary artifacts, so they must be readable by whoever
	// consumes them, not only by the uid that wrote them. The process umask
	// still applies on top of the requested mode, so the expectation is what a
	// 0644 request yields on this host rather than a literal 0644, which would
	// fail for anyone running the suite under umask 077.
	probe := filepath.Join(dir, "mode-probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatalf("write mode probe: %v", err)
	}
	probeInfo, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat mode probe: %v", err)
	}
	for _, sidecar := range []string{".sig", ".pem", ".intoto.jsonl"} {
		info, err := os.Stat(path + sidecar)
		if err != nil {
			t.Fatalf("stat %s sidecar: %v", sidecar, err)
		}
		if got, want := info.Mode().Perm(), probeInfo.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o (0644 under this umask)", path+sidecar, got, want)
		}
	}
}

// newFulcioStub issues short-lived certificates the way Fulcio does: it reads
// the public key out of the request, checks the proof of possession against the
// token's subject, and answers with a chain whose leaf carries that subject as
// its URI SAN.
func newFulcioStub(t *testing.T) *httptest.Server {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"cdxsign test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	spiffeURL, err := url.Parse(testSpiffeID)
	if err != nil {
		t.Fatalf("parse %q: %v", testSpiffeID, err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/signingCert" {
			http.NotFound(w, r)
			return
		}

		var request struct {
			Credentials struct {
				OIDCIdentityToken string `json:"oidcIdentityToken"`
			} `json:"credentials"`
			PublicKeyRequest struct {
				PublicKey struct {
					Algorithm string `json:"algorithm"`
					Content   string `json:"content"`
				} `json:"publicKey"`
				ProofOfPossession string `json:"proofOfPossession"`
			} `json:"publicKeyRequest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "unreadable request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if request.Credentials.OIDCIdentityToken != testIdentityToken {
			http.Error(w, "unexpected identity token", http.StatusUnauthorized)
			return
		}

		block, _ := pem.Decode([]byte(request.PublicKeyRequest.PublicKey.Content))
		if block == nil {
			http.Error(w, "public key is not PEM", http.StatusBadRequest)
			return
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			http.Error(w, "unreadable public key: "+err.Error(), http.StatusBadRequest)
			return
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			http.Error(w, "not an ECDSA key", http.StatusBadRequest)
			return
		}

		proof, err := base64.StdEncoding.DecodeString(request.PublicKeyRequest.ProofOfPossession)
		if err != nil {
			http.Error(w, "unreadable proof of possession: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Fulcio signs the token's subject, so the stub verifies against the
		// same bytes; this is what binds the key being certified to the token.
		subject := sha256.Sum256([]byte(testSpiffeID))
		if !ecdsa.VerifyASN1(key, subject[:], proof) {
			http.Error(w, "proof of possession failed", http.StatusUnauthorized)
			return
		}

		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{Organization: []string{"cdxsign test"}},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(10 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			URIs:         []*url.URL{spiffeURL},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, key, caKey)
		if err != nil {
			http.Error(w, "cannot issue certificate: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Fulcio answers with the chain under one of two keys; this stub picks
		// the embedded-SCT shape.
		chain := []string{
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"signedCertificateEmbeddedSct": map[string]any{
				"chain": map[string]any{"certificates": chain},
			},
		}); err != nil {
			t.Errorf("fulcio stub: write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newRekorStub witnesses signatures the way Rekor does: it records the hashed
// rekord and answers with the new entry. The index counts up per call so the
// test can tell the first signature's entry from the rest.
func newRekorStub(t *testing.T, firstIndex int64) *httptest.Server {
	t.Helper()

	var entries atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Kind string `json:"kind"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "unreadable request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if body.Kind != "hashedrekord" {
			http.Error(w, "unexpected kind "+body.Kind, http.StatusBadRequest)
			return
		}

		index := firstIndex + entries.Add(1) - 1
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(map[string]struct {
			LogIndex int64 `json:"logIndex"`
		}{testRekorUUID: {LogIndex: index}}); err != nil {
			t.Errorf("rekor stub: write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
