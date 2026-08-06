package cdxsign

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The Fulcio exchange itself is covered in vdb-cyclonedx, against a stand-in
// that verifies the proof of possession the way Fulcio does. What matters here
// is the behaviour a customer sees: an unsigned document is a normal outcome,
// not a failure, and nothing is written that pretends otherwise.

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
	t.Setenv("SIGSTORE_ID_TOKEN", "eyJhbGciOiJSUzI1NiJ9."+
		"eyJzdWIiOiJzcGlmZmU6Ly9zaWdzdG9yZS52dWxuZXRpeC5jb20vY29kZS1zY2FubmVyIn0.sig")
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
