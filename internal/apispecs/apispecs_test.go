package apispecs

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverFindsSpecsAndSkipsNoise(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "api/openapi.yaml", `
openapi: 3.0.3
info: {title: Pets, version: "1"}
paths:
  /pets:
    get: {responses: {"200": {description: ok}}}
`)
	// A Swagger 2.0 file under an odd name: found by sniffing.
	write(t, dir, "contracts/legacy.yaml", `
swagger: "2.0"
info: {title: Legacy, version: "1"}
paths:
  /things/{id}:
    get: {responses: {"200": {description: ok}}}
`)
	// Not a spec, must be skipped.
	write(t, dir, "package.json", `{"name":"app","dependencies":{"fastapi":"1"}}`)
	// A vendored spec, must be skipped.
	write(t, dir, "node_modules/foo/openapi.json", `{"openapi":"3.0.0","paths":{}}`)

	found, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d: %+v", len(found), paths(found))
	}
	if found[0].Path != "api/openapi.yaml" || found[1].Path != "contracts/legacy.yaml" {
		t.Fatalf("paths = %v", paths(found))
	}
	if found[1].Document.Source.Format != "swagger" {
		t.Fatalf("format = %v", found[1].Document.Source.Format)
	}
}

func TestGenerators(t *testing.T) {
	g := Generators([]string{"fastapi", "left-pad"})
	if len(g) != 1 || g[0].Framework != "fastapi" {
		t.Fatalf("generators = %+v", g)
	}
}

func paths(f []Found) []string {
	out := make([]string, len(f))
	for i := range f {
		out[i] = f[i].Path
	}
	return out
}
