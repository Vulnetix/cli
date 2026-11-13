//go:build linux

package lsmguard

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/internal/sensor/decide"
)

func TestCheckBPFLSM(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if err := checkBPFLSM(write("with", "lockdown,capability,landlock,yama,bpf\n")); err != nil {
		t.Errorf("a list naming bpf: %v", err)
	}
	err := checkBPFLSM(write("without", "lockdown,capability,landlock,yama,apparmor\n"))
	if err == nil || !strings.Contains(err.Error(), "add bpf to lsm=") {
		t.Errorf("a list without bpf must refuse with the fix, got %v", err)
	}
	if err := checkBPFLSM(filepath.Join(dir, "absent")); err != nil {
		t.Errorf("an unreadable list leaves the decision to the attach: %v", err)
	}
}

func TestResolveEntries(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"usr/bin/nc", "usr/bin/curl"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A hard link is the same file, so it is the same key.
	if err := os.Link(filepath.Join(root, "usr/bin/nc"), filepath.Join(root, "usr/bin/ncat")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}

	rule := func(id string) decide.RuleRef { return decide.RuleRef{Table: "sigma", UUID: id} }
	entries := []Entry{
		{Path: "/usr/bin/nc", Rule: rule("a")},
		{Path: "/usr/bin/missing", Rule: rule("b")},
		{Path: "/usr/bin/ncat", Rule: rule("c")}, // same file as entry 0
		{Path: "/usr/lib", Rule: rule("d")},      // a directory is not a program
		{Path: "/usr/bin/curl", Rule: rule("e")},
	}
	want, paths, missing := resolveEntries(entries, root)

	if !reflect.DeepEqual(missing, []string{"/usr/bin/missing", "/usr/lib"}) {
		t.Errorf("missing = %v", missing)
	}
	if len(want) != 2 || len(paths) != 2 {
		t.Fatalf("want %v, paths %v: two distinct files", want, paths)
	}
	ncKey, ok := statKey(filepath.Join(root, "usr/bin/nc"))
	if !ok {
		t.Fatal("stat nc")
	}
	if want[ncKey] != 0 || paths[ncKey] != "/usr/bin/nc" {
		t.Errorf("the first entry naming a file keeps it: rule %d, path %q", want[ncKey], paths[ncKey])
	}
	curlKey, _ := statKey(filepath.Join(root, "usr/bin/curl"))
	if want[curlKey] != 4 || paths[curlKey] != "/usr/bin/curl" {
		t.Errorf("curl: rule %d, path %q; the index is the entry's position", want[curlKey], paths[curlKey])
	}
}

func TestRefusalFor(t *testing.T) {
	entries := []Entry{
		{Path: "/usr/bin/nc", Rule: decide.RuleRef{Table: "sigma", UUID: "a"}},
		{Path: "/usr/bin/curl", Rule: decide.RuleRef{Table: "sigma", UUID: "b"}},
	}
	known := fileKey{Ino: 7, Dev: 1}
	paths := map[fileKey]string{known: "/usr/bin/ncat"}

	// A synced file is named by the path synced for it, with its rule.
	r := refusalFor(rawRefusal{key: known, rule: 0, pid: 42, enforced: true}, entries, paths)
	if r != (Refusal{Path: "/usr/bin/ncat", Rule: entries[0].Rule, PID: 42, Enforced: true}) {
		t.Errorf("known key: %+v", r)
	}

	// An unknown key falls back to the rule's own path.
	r = refusalFor(rawRefusal{key: fileKey{Ino: 99}, rule: 1, pid: 5}, entries, paths)
	if r != (Refusal{Path: "/usr/bin/curl", Rule: entries[1].Rule, PID: 5}) {
		t.Errorf("unknown key: %+v", r)
	}

	// A rule index outside the current entries names no rule.
	r = refusalFor(rawRefusal{key: known, rule: 9, pid: 6}, entries, paths)
	if r != (Refusal{Path: "/usr/bin/ncat", PID: 6}) {
		t.Errorf("out-of-range rule with a known key: %+v", r)
	}
	r = refusalFor(rawRefusal{key: fileKey{Ino: 99}, rule: 9}, entries, paths)
	if r != (Refusal{}) {
		t.Errorf("out-of-range rule and unknown key: %+v", r)
	}
}
