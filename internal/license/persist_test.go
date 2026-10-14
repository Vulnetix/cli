package license

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Never let a test read or write the developer's real licence store.
	dir, err := os.MkdirTemp("", "vulnetix-licenses-")
	if err != nil {
		panic(err)
	}
	licenseStoreDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestStoredLicenseIsReusedAcrossRuns(t *testing.T) {
	calls := 0
	fetch := func() string { calls++; return "MIT" }
	if got := storedOrFetch("registry", "npm:left-pad:1.3.0", fetch); got != "MIT" {
		t.Fatalf("first lookup = %q", got)
	}
	if got := storedOrFetch("registry", "npm:left-pad:1.3.0", fetch); got != "MIT" || calls != 1 {
		t.Fatalf("second lookup = %q after %d fetches, want the stored MIT after 1", got, calls)
	}
	if got := storedOrFetch("depsdev", "npm:left-pad:1.3.0", func() string { return "ISC" }); got != "ISC" {
		t.Fatalf("a different source shared the stored answer: %q", got)
	}
}

func TestMissesAreNotStored(t *testing.T) {
	calls := 0
	fetch := func() string { calls++; return "" } // a timeout and a licence-less release look the same
	storedOrFetch("registry", "pypi:flaky:1.0", fetch)
	storedOrFetch("registry", "pypi:flaky:1.0", fetch)
	if calls != 2 {
		t.Fatalf("a miss was remembered: %d fetches, want 2", calls)
	}
	if got := storedOrFetch("registry", "pypi:flaky:1.0", func() string { return "BSD-3-Clause" }); got != "BSD-3-Clause" {
		t.Fatalf("licence found after earlier misses = %q", got)
	}
}

func TestStoredLicenseExpires(t *testing.T) {
	key := "cargo:serde:1.0.0"
	raw, _ := json.Marshal(storedLicense{License: "MIT", At: time.Now().Add(-licenseTTL - time.Hour).Unix()})
	path := licenseStorePath("registry", key)
	if err := os.MkdirAll(licenseStoreDir+"/registry", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := storedOrFetch("registry", key, func() string { return "Apache-2.0" }); got != "Apache-2.0" {
		t.Fatalf("an expired answer was reused: %q", got)
	}
}

func TestRegistryScopeIsNeverAGitHubOwner(t *testing.T) {
	for _, name := range []string{"@std/path", "@types/node", "@cliffy/command"} {
		if o, r := resolveOwnerRepo(name, "jsr"); o != "" || r != "" {
			t.Errorf("%s resolved to GitHub %s/%s; a leading @ is a registry scope", name, o, r)
		}
	}
	if o, r := resolveOwnerRepo("kemalcr/kemal", "crystal"); o != "kemalcr" || r != "kemal" {
		t.Errorf("owner/repo no longer resolves: %s/%s", o, r)
	}
}
