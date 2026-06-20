package reachability

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// TestScanRoot_ConcurrencyParity proves the parallel file scan produces the
// byte-identical Transitive match slice (same order) and Executed set as the
// legacy serial walk — VULNETIX_REACHABILITY_CONCURRENCY changes only how many
// files are analysed at once, never the result. Run with -race to catch any
// unsynchronised shared state.
func TestScanRoot_ConcurrencyParity(t *testing.T) {
	files := map[string]string{
		"readme.md":            "# not source, must be ignored\n",
		"a/b/deep.js":          "const _ = require('lodash');\n_.template('x');\n",
		"z/last.js":            "const _ = require('lodash');\nfunction z(i){ return _.template(i); }\n",
		"node_modules/skip.js": "const _ = require('lodash'); _.template('skip me');\n",
	}
	for i := range 60 {
		if i%3 == 0 {
			files[fmt.Sprintf("src/m%02d.js", i)] = "const _ = require('lodash');\nfunction r(i){ return _.template(i); }\n"
		} else {
			files[fmt.Sprintf("src/n%02d.js", i)] = "function noop(){ return 1; }\n"
		}
	}
	root := writeTempProject(t, files)
	q := vdb.TreeSitterQuery{
		VulnID:    "CVE-PAR",
		Language:  "javascript",
		Name:      "js-member-call",
		QueryText: jsMemberCallQuery,
		QueryHash: "hash-par",
	}

	run := func(conc string) *Result {
		t.Setenv("VULNETIX_REACHABILITY_CONCURRENCY", conc)
		res, err := Scan(context.Background(), NewEngine(), ScanRequest{
			ProjectRoot: root,
			Queries:     []vdb.TreeSitterQuery{q},
			Mode:        ModeTransitive,
		})
		if err != nil {
			t.Fatalf("conc=%s: Scan: %v", conc, err)
		}
		return res
	}

	serial := run("1")
	parallel := run("8")

	if len(serial.Transitive) == 0 {
		t.Fatalf("fixture produced no matches; test is not exercising the merge path")
	}
	sj, _ := json.Marshal(serial.Transitive)
	pj, _ := json.Marshal(parallel.Transitive)
	if string(sj) != string(pj) {
		t.Errorf("Transitive slice differs by concurrency (order or content):\n serial  =%s\n parallel=%s", sj, pj)
	}
	if !reflect.DeepEqual(serial.Executed, parallel.Executed) {
		t.Errorf("Executed set differs by concurrency: serial=%v parallel=%v", serial.Executed, parallel.Executed)
	}
	// node_modules must be skipped under both.
	for _, m := range parallel.Transitive {
		if got := m.File; len(got) >= 12 && got[:12] == "node_modules" {
			t.Errorf("node_modules should be skipped, saw match in %s", got)
		}
	}
}
