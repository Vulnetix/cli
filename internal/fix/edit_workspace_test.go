package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Vulnetix/cli#177: a monorepo's findings come from its one lockfile at the
// workspace root, so a direct bump maps to the root package.json. The member
// that declares the dependency is the manifest to edit; the root often declares
// nothing, and the edit failed with "could not locate".
func TestApplyDirectBumpEditsTheDeclaringWorkspaceMember(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"workspaces": ["packages/*", "tools/*"], "dependencies": {"dotenv": "^16.4.5"}}`)
	write("bun.lock", "{}")
	write("packages/app/package.json", `{"dependencies": {"express": "^4.21.0"}}`)
	write("tools/fixed-point/package.json", `{"dependencies": {"express": "~4.20.0", "lodash": "^4.17.21"}}`)
	write("tools/other/package.json", `{"dependencies": {"lodash": "^4.17.21"}}`)

	err := Apply(root, []FixCandidate{{
		PackageName: "express", Ecosystem: "npm", SourceFile: "package.json",
		TargetVer: "4.22.3", Method: MethodDirectBump,
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, rel := range []string{"packages/app/package.json", "tools/fixed-point/package.json"} {
		if !strings.Contains(read(rel), "4.22.3") {
			t.Errorf("%s not bumped: %s", rel, read(rel))
		}
	}
	if strings.Contains(read("tools/other/package.json"), "express") {
		t.Error("a member that does not declare express was edited")
	}
	if strings.Contains(read("package.json"), "express") {
		t.Error("the root gained a dependency it did not declare")
	}

	// Not a workspace root: the honest error stays.
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "package.json"), []byte(`{"dependencies": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err = Apply(plain, []FixCandidate{{PackageName: "express", Ecosystem: "npm", SourceFile: "package.json", TargetVer: "4.22.3", Method: MethodDirectBump}})
	if err == nil || !strings.Contains(err.Error(), "could not locate express") {
		t.Errorf("want could-not-locate outside a workspace, got %v", err)
	}
}
