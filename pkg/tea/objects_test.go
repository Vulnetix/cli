package tea

import "testing"

// The media type decides whether a consumer's parser accepts an artifact, so
// being wrong is worse than being unspecific.
func TestMediaTypeForFile(t *testing.T) {
	cases := map[string]string{
		"bom.cdx.json":       "application/vnd.cyclonedx+json",
		"vulnetix.cdx.json":  "application/vnd.cyclonedx+json",
		"sbom.spdx.json":     "application/spdx+json",
		"results.sarif":      "application/sarif+json",
		"results.sarif.json": "application/sarif+json",
		"openvex.json":       "application/vnd.openvex+json",
		"metadata.json":      "application/json",
		"CHANGELOG.md":       "text/plain",
		"artifact.bin":       "application/octet-stream",
		"no-extension":       "application/octet-stream",
	}
	for name, want := range cases {
		if got := MediaTypeForFile(name); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}

// OTHER is the default on purpose: telling a consumer a file is a bill of
// materials when it might not be tells them to parse it as one.
func TestArtifactTypeForFile(t *testing.T) {
	cases := map[string]string{
		"bom.cdx.json":     "BOM",
		"sbom.spdx.json":   "BOM",
		"app.cbom.json":    "BOM",
		"model.aibom.json": "BOM",
		"openvex.json":     "VULNERABILITIES",
		"results.sarif":    "VULNERABILITIES",
		"provenance.json":  "ATTESTATION",
		"slsa.intoto.json": "ATTESTATION",
		"CHANGELOG.md":     "RELEASE_NOTES",
		"LICENSE.txt":      "LICENSE",
		"mystery.bin":      "OTHER",
	}
	for name, want := range cases {
		if got := ArtifactTypeForFile(name); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}

// The digest is what lets the server reject a truncated upload, so its exact
// encoding matters: a header the server cannot parse is a check that silently
// does not happen.
func TestContentDigestIsRFC9530(t *testing.T) {
	// sha-256 of the empty string.
	if got := ContentDigest(nil); got != "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" {
		t.Errorf("empty body digest: %s", got)
	}
	a := ContentDigest([]byte("one"))
	b := ContentDigest([]byte("two"))
	if a == b {
		t.Error("different bodies produced the same digest")
	}
}

func TestNormaliseDomain(t *testing.T) {
	ok := map[string]string{
		"products.example.com":                      "products.example.com",
		"Products.Example.COM":                      "products.example.com",
		"https://products.example.com/tea/v1":       "products.example.com",
		"  https://products.example.com  ":          "products.example.com",
		"urn:tei:uuid:products.example.com:abc-123": "products.example.com",
		"products.example.com:8443":                 "products.example.com",
	}
	for in, want := range ok {
		got, err := NormaliseDomain(in)
		if err != nil {
			t.Errorf("%q was refused: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q became %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "   ", "localhost", "not a domain", "urn:tei:uuid"} {
		if got, err := NormaliseDomain(in); err == nil {
			t.Errorf("%q was accepted as %q", in, got)
		}
	}
}

// Pointing a user's tooling at a provider's beta API is not a decision to make
// on their behalf, so a stable version wins even when a pre-release sorts
// higher.
func TestRootFromPrefersPriorityThenStable(t *testing.T) {
	low, high := 0.2, 0.9
	doc := &WellKnown{
		SchemaVersion: 1,
		Endpoints: []struct {
			URL      string   `json:"url"`
			Versions []string `json:"versions"`
			Priority *float64 `json:"priority,omitempty"`
		}{
			{URL: "https://low.example.com", Versions: []string{"1.0.0"}, Priority: &low},
			{URL: "https://high.example.com", Versions: []string{"0.4.0", "1.0.0", "1.1.0-beta.1"}, Priority: &high},
		},
	}
	if got := RootFrom(doc); got != "https://high.example.com/v1.0.0" {
		t.Errorf("got %q, want the higher-priority endpoint at its newest stable version", got)
	}
	if got := RootFrom(nil); got != "" {
		t.Errorf("a nil document produced %q", got)
	}
}
