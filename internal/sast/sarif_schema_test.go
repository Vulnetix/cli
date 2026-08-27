package sast

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Every SARIF document the scan family emits is uploaded to Vulnetix and, for
// many users, to GitHub code scanning. Both validate. We shipped documents where
// result.kind carried our own taxonomy ("sast", "secrets", "iac", "oci") instead
// of a value from SARIF's enum, which made every result invalid — 2,017 errors in
// one `sast` run — and nothing in the test suite noticed, because the one unit
// test happened to use "pass", which is in the enum.
//
// The schema is read from the repo's own schemas/ directory rather than embedded:
// this is the same file `just sync-schemas` copies into internal/analyze, and a
// test reading it directly cannot drift from it.
func TestBuildSARIFValidatesAgainstSchema(t *testing.T) {
	const schemaPath = "../../schemas/third_party/sarif-2.1.0.schema.json"
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read SARIF schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("parse SARIF schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	const schemaURL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	if err := c.AddResource(schemaURL, doc); err != nil {
		t.Fatalf("add SARIF schema: %v", err)
	}
	schema, err := c.Compile(schemaURL)
	if err != nil {
		t.Fatalf("compile SARIF schema: %v", err)
	}

	// One finding per rule kind the engine produces, so a regression on any of
	// them fails here rather than in a customer's ingestion pipeline.
	var findings []Finding
	for _, kind := range []string{"sast", "secrets", "iac", "oci"} {
		findings = append(findings, Finding{
			RuleID:      "vnx-" + kind + "-001",
			Message:     kind + " finding",
			ArtifactURI: "main.go",
			Severity:    "high",
			Level:       "error",
			StartLine:   1,
			EndLine:     2,
			Snippet:     "bad code",
			Fingerprint: "abc123",
			Metadata:    &RuleMetadata{Kind: kind},
		})
	}

	log := BuildSARIF(findings, nil, "1.0.0")
	encoded, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("re-parse SARIF: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("BuildSARIF produced a document that fails SARIF 2.1.0 validation:\n%v", err)
	}
}
