package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// manifestBeforeTests is the command tree as the binary builds it, taken before any test
// runs: some tests add flags to or reconfigure the shared commands, and the manifest is
// of the tree `vulnetix __manifest` prints, not of a tree a test has touched.
var manifestBeforeTests []byte

func TestMain(m *testing.M) {
	b, err := json.Marshal(BuildCommandManifest())
	if err != nil {
		panic(err)
	}
	manifestBeforeTests = b
	os.Exit(m.Run())
}

// docs/command-manifest.json is what the documentation is validated against. It fell
// behind the command tree (api, config plan/apply/export were missing) because nothing
// checked it. This fails when a command, flag or subcommand changes without
// `just gen-command-manifest`.
func TestCommandManifestMatchesTheCommandTree(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "command-manifest.json"))
	if err != nil {
		t.Fatalf("read the committed manifest: %v", err)
	}
	var committed CommandManifest
	if err := json.Unmarshal(raw, &committed); err != nil {
		t.Fatalf("the committed manifest is not valid JSON: %v", err)
	}
	// Both sides through JSON, so they compare the same way.
	var built CommandManifest
	if err := json.Unmarshal(manifestBeforeTests, &built); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(committed, built) {
		return
	}
	var added, removed, changed []string
	for name, c := range built.Commands {
		old, ok := committed.Commands[name]
		switch {
		case !ok:
			added = append(added, name)
		case !reflect.DeepEqual(old, c):
			changed = append(changed, name)
		}
	}
	for name := range committed.Commands {
		if _, ok := built.Commands[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	t.Fatalf("docs/command-manifest.json is out of date; run `just gen-command-manifest`.\nnew: %v\ngone: %v\nchanged: %v", added, removed, changed)
}
