package apispecs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const onePetSpec = `
openapi: 3.0.3
info: {title: Pets, version: "1"}
paths:
  /pets:
    get: {responses: {"200": {description: ok}}}
`

func TestDiscoverSkipsEmptyOversizedAndBrokenFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a/openapi.yaml", onePetSpec)
	// Zero bytes, under a spec name: skipped, not an error.
	write(t, dir, "b/openapi.json", "")
	// A spec name whose content does not parse: skipped, and the walk goes on.
	write(t, dir, "c/openapi.yaml", "openapi: [this is: not: valid")
	write(t, dir, "d/swagger.yaml", `
swagger: "2.0"
info: {title: Legacy, version: "1"}
paths:
  /a: {get: {responses: {"200": {description: ok}}}}
  /b: {post: {responses: {"200": {description: ok}}}}
`)
	// Over the size cap: never read. A sparse file costs no disk.
	big := filepath.Join(dir, "e", "openapi.json")
	if err := os.MkdirAll(filepath.Dir(big), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSpecBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	found, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(found); strings.Join(got, ",") != "a/openapi.yaml,d/swagger.yaml" {
		t.Fatalf("found %v, want the two valid specs in path order", got)
	}
}

func TestSummary(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "one/openapi.yaml", onePetSpec)
	write(t, dir, "two/openapi.yaml", `
openapi: 3.0.3
info: {title: Pets, version: "1"}
paths:
  /pets:
    get: {responses: {"200": {description: ok}}}
    post: {responses: {"200": {description: ok}}}
`)
	found, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found %v", paths(found))
	}

	one := Summary(found[0])
	if !strings.HasPrefix(one, "one/openapi.yaml: ") || !strings.HasSuffix(one, ", 1 operation") {
		t.Errorf("Summary = %q, want the path and a singular operation count", one)
	}
	two := Summary(found[1])
	if !strings.HasSuffix(two, ", 2 operations") {
		t.Errorf("Summary = %q, want a plural operation count", two)
	}
	if strings.Contains(one, "loss") {
		t.Errorf("no losses means no losses clause: %q", one)
	}
}

func TestPluralAndItoa(t *testing.T) {
	for n, want := range map[int]string{0: "0", 7: "7", 10: "10", 12345: "12345"} {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
	for _, tt := range []struct {
		n    int
		word string
		want string
	}{
		{0, "operation", "0 operations"},
		{1, "operation", "1 operation"},
		{3, "operation", "3 operations"},
		// Summary counts conversion losses; "losss" is what a bare +s makes.
		{1, "loss", "1 loss"},
		{2, "loss", "2 losses"},
	} {
		if got := plural(tt.n, tt.word); got != tt.want {
			t.Errorf("plural(%d, %q) = %q, want %q", tt.n, tt.word, got, tt.want)
		}
	}
}
