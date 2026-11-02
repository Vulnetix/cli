package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestGeneratedFilesAreCurrent fails when an action.yml, a docs page or
// action-lib/commands.sh differs from what the spec generates. Fix it with
// `go generate ./tools/actiongen`.
func TestGeneratedFilesAreCurrent(t *testing.T) {
	for name, want := range generate() {
		got, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Errorf("%s: %v (run go generate ./tools/actiongen)", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: run go generate ./tools/actiongen", name)
		}
	}
}

// Nothing a caller controls may be interpolated into a script: inputs reach
// scripts only through env. An expression inside a run: block is the
// injection this layout exists to prevent.
func TestNoExpressionInsideAScript(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join("..", "..", "*", "action.yml"))
	paths = append(paths, filepath.Join("..", "..", "action.yml"))
	runLine := regexp.MustCompile(`^\s*run:\s*(.*)$`)
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		inBlock, indent := false, 0
		for i, l := range lines {
			if inBlock {
				cur := len(l) - len(strings.TrimLeft(l, " "))
				if strings.TrimSpace(l) != "" && cur <= indent {
					inBlock = false
				} else if strings.Contains(l, "${{") {
					t.Errorf("%s:%d: expression inside a script: %s", p, i+1, strings.TrimSpace(l))
				}
			}
			if m := runLine.FindStringSubmatch(l); m != nil {
				if strings.Contains(m[1], "${{") {
					t.Errorf("%s:%d: expression inside a script: %s", p, i+1, strings.TrimSpace(l))
				}
				if m[1] == "|" || m[1] == ">" {
					inBlock, indent = true, len(l)-len(strings.TrimLeft(l, " "))
				}
			}
		}
		if bytes.Contains(raw, []byte("eval ")) {
			t.Errorf("%s uses eval", p)
		}
	}
}

// Third-party actions are pinned by commit SHA.
func TestThirdPartyActionsArePinned(t *testing.T) {
	sha := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}( #.*)?$`)
	for _, u := range []string{uploadArtifact, attestBuild, attestSBOM} {
		if !sha.MatchString(u) {
			t.Errorf("%s is not pinned by SHA", u)
		}
	}
}

func TestEverySpecActionHasADocsPage(t *testing.T) {
	files := generate()
	for _, a := range actions {
		if _, ok := files["docs/github-actions/"+a.Name+".md"]; !ok {
			t.Errorf("%s has no docs page", a.Name)
		}
	}
}
