package attest

import "testing"

func TestParseSLSAv02(t *testing.T) {
	payload := []byte(`{
	  "_type":"https://in-toto.io/Statement/v0.1",
	  "predicateType":"https://slsa.dev/provenance/v0.2",
	  "subject":[{"name":"sbom.cdx.json","digest":{"sha256":"abc123"}}],
	  "predicate":{
	    "builder":{"id":"https://github.com/actions/runner"},
	    "buildType":"https://github.com/actions/workflow@v1",
	    "invocation":{"configSource":{
	      "uri":"git+https://github.com/acme/repo@refs/heads/main",
	      "digest":{"sha1":"deadbeef"},
	      "entryPoint":".github/workflows/release.yml"
	    }}
	  }
	}`)

	p := parsePredicate(payload)
	if p == nil {
		t.Fatal("v0.2 provenance was not recognised")
	}
	if p.Kind != KindProvenance || p.SLSAVersion != "v0.2" {
		t.Errorf("kind = %q version = %q", p.Kind, p.SLSAVersion)
	}
	if p.Builder != "https://github.com/actions/runner" {
		t.Errorf("builder = %q", p.Builder)
	}
	if p.SourceURI == "" || p.SourceRevision != "sha1:deadbeef" {
		t.Errorf("source = %q @ %q", p.SourceURI, p.SourceRevision)
	}
	if p.Invocation != ".github/workflows/release.yml" {
		t.Errorf("invocation = %q", p.Invocation)
	}
}

// TestParseSLSAv1 covers the other shape. v1 moved the builder under runDetails
// and the source under buildDefinition, so one parser cannot serve both.
func TestParseSLSAv1(t *testing.T) {
	payload := []byte(`{
	  "_type":"https://in-toto.io/Statement/v1",
	  "predicateType":"https://slsa.dev/provenance/v1",
	  "subject":[{"name":"app","digest":{"sha256":"feed01"}}],
	  "predicate":{
	    "buildDefinition":{
	      "buildType":"https://actions.github.io/buildtypes/workflow/v1",
	      "externalParameters":{"workflow":{
	        "ref":"refs/heads/main","repository":"https://github.com/acme/repo",
	        "path":".github/workflows/build.yml"}},
	      "resolvedDependencies":[
	        {"uri":"git+https://github.com/acme/repo@refs/heads/main","digest":{"gitCommit":"cafe01"}}
	      ]
	    },
	    "runDetails":{"builder":{"id":"https://github.com/acme/builder"}}
	  }
	}`)

	p := parsePredicate(payload)
	if p == nil {
		t.Fatal("v1 provenance was not recognised")
	}
	if p.SLSAVersion != "v1" {
		t.Errorf("version = %q", p.SLSAVersion)
	}
	if p.Builder != "https://github.com/acme/builder" {
		t.Errorf("builder = %q — v1 puts it under runDetails", p.Builder)
	}
	if p.SourceURI == "" || p.SourceRevision != "gitCommit:cafe01" {
		t.Errorf("source = %q @ %q", p.SourceURI, p.SourceRevision)
	}
}

func TestParsePredicateKinds(t *testing.T) {
	tests := map[string]PredicateKind{
		`{"_type":"x","predicateType":"https://spdx.dev/Document","predicate":{}}`:                KindSBOM,
		`{"_type":"x","predicateType":"https://cyclonedx.org/bom","predicate":{}}`:                KindSBOM,
		`{"_type":"x","predicateType":"https://in-toto.io/attestation/sbom/v0.1","predicate":{}}`: KindSBOM,
		`{"_type":"x","predicateType":"https://example.com/custom/v1","predicate":{}}`:            KindOther,
	}
	for payload, want := range tests {
		p := parsePredicate([]byte(payload))
		if p == nil {
			t.Errorf("parsePredicate(%s) = nil", payload)
			continue
		}
		if p.Kind != want {
			t.Errorf("parsePredicate(%s).Kind = %q, want %q", payload, p.Kind, want)
		}
	}

	// Not a statement at all.
	if p := parsePredicate([]byte(`{"bomFormat":"CycloneDX"}`)); p != nil {
		t.Errorf("a plain SBOM was read as a predicate: %+v", p)
	}
	if p := parsePredicate(nil); p != nil {
		t.Error("nil payload produced a predicate")
	}
}

// TestClaimReportsFieldsNotALevel pins the deliberate refusal to output a SLSA
// level. A level is a property of the build platform and its controls, which no
// consumer can determine by reading a document the build produced.
func TestClaimReportsFieldsNotALevel(t *testing.T) {
	complete := parsePredicate([]byte(`{
	  "_type":"x","predicateType":"https://slsa.dev/provenance/v0.2",
	  "subject":[{"name":"a","digest":{"sha256":"abc"}}],
	  "predicate":{"builder":{"id":"b"},"buildType":"t",
	    "invocation":{"configSource":{"uri":"git+https://x","digest":{"sha1":"d"}}}}
	}`))
	claim := complete.Claim()
	if !claim.Complete() {
		t.Errorf("complete provenance reported incomplete: %+v", claim)
	}
	if len(claim.Missing) != 0 {
		t.Errorf("Missing = %v, want empty", claim.Missing)
	}

	// A shortfall names the absent field, so it is actionable.
	partial := parsePredicate([]byte(`{
	  "_type":"x","predicateType":"https://slsa.dev/provenance/v0.2",
	  "subject":[{"name":"a"}],
	  "predicate":{"buildType":"t"}
	}`))
	claim = partial.Claim()
	if claim.Complete() {
		t.Error("provenance with no builder, source or digest reported complete")
	}
	if len(claim.Missing) != 3 {
		t.Errorf("Missing = %v, want builder, source and subject digest", claim.Missing)
	}

	// A non-provenance predicate makes no provenance claim at all.
	var none *Predicate
	if c := none.Claim(); c.HasProvenance {
		t.Error("a nil predicate claimed provenance")
	}
}
