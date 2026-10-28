package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-sca-match/ghaudit"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var ghaUpdateGolden = flag.Bool("update-gha-golden", false, "rewrite cmd/testdata/gha/audit.sarif.json")

// ghaGoldenFiles is a checkout with one of most kinds of workflow flaw the
// engine reports offline: injection through env and a composite action,
// pull_request_target running PR code, unpinned actions, write-all
// permissions, secrets inherited by a reusable workflow.
var ghaGoldenFiles = map[string]string{
	".github/workflows/ci.yml": `on:
  pull_request_target:
  issue_comment:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "$TITLE" && echo "${{ github.event.comment.body }}"
      - uses: ./.github/actions/greet
        with:
          who: ${{ github.head_ref }}
      - run: npm ci && npm test
  release:
    uses: acme/shared/.github/workflows/release.yml@main
    secrets: inherit
`,
	".github/actions/greet/action.yml": `name: greet
inputs:
  who:
    required: true
runs:
  using: composite
  steps:
    - run: echo "hello ${{ inputs.who }}"
      shell: bash
`,
}

// The SARIF gha produces is what Vulnetix ingests and what users upload to
// GitHub code scanning: it must be valid SARIF 2.1.0, and a change to it must
// be a reviewed change to the golden file.
func TestGHAAuditSARIFIsValidAndStable(t *testing.T) {
	dir := t.TempDir()
	for p, body := range ghaGoldenFiles {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	opt := ghaTaskOptions{format: "sarif", offline: true, maxActionRefs: 40}
	if err := runGHATask(context.Background(), &out, &errOut, ghaudit.AllTasks, dir, opt); err != nil {
		t.Fatalf("gha audit: %v\n%s", err, errOut.String())
	}

	raw, err := os.ReadFile("../schemas/third_party/sarif-2.1.0.schema.json")
	if err != nil {
		t.Fatalf("read SARIF schema: %v", err)
	}
	sdoc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	const schemaURL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, sdoc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if err := schema.Validate(inst); err != nil {
		t.Fatalf("gha SARIF does not validate: %v", err)
	}

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || len(doc.Runs) != 1 {
		t.Fatalf("runs: %v", err)
	}
	if doc.Runs[0].Tool.Driver.Name != ghaudit.ToolName {
		t.Errorf("driver = %q, want %q (the name SaaS maps to the IAC category)", doc.Runs[0].Tool.Driver.Name, ghaudit.ToolName)
	}
	seen := map[string]bool{}
	for _, r := range doc.Runs[0].Results {
		seen[r.RuleID] = true
	}
	for _, id := range []string{"VNX-GH-001"} {
		if !seen[id] {
			t.Errorf("expected a %s result, got %v", id, seen)
		}
	}
	if len(seen) < 5 {
		t.Errorf("the fixture should trip several rules, got %v", seen)
	}

	golden := filepath.Join("testdata", "gha", "audit.sarif.json")
	if *ghaUpdateGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update-gha-golden): %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(out.Bytes())) {
		t.Errorf("gha audit SARIF changed; review and run go test ./cmd -run TestGHAAuditSARIFIsValidAndStable -update-gha-golden")
	}
}
