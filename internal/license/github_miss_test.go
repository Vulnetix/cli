package license

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeGH puts a gh on PATH that succeeds for `auth status` and fails every
// `api` call, writing stderr to its standard error.
func fakeGH(t *testing.T, stderr string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n[ \"$1\" = auth ] && exit 0\necho '" + stderr + "' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	ghCLIOnce = sync.Once{}
	t.Cleanup(func() { ghCLIOnce = sync.Once{} })
}

func TestGitHubMissIsDefinitiveOnlyOn404(t *testing.T) {
	fakeGH(t, "gh: Not Found (HTTP 404)")
	if lic, definitive := resolveRepoLicenseChecked("someone", "gone"); lic != "" || !definitive {
		t.Fatalf("all-404 lookup: lic=%q definitive=%v, want a definitive miss", lic, definitive)
	}

	fakeGH(t, "error connecting to api.github.com: i/o timeout")
	if lic, definitive := resolveRepoLicenseChecked("someone", "flaky"); lic != "" || definitive {
		t.Fatalf("timed-out lookup: lic=%q definitive=%v, a timeout must never be a definitive miss", lic, definitive)
	}
}

func TestStoredMissExpiresAfterADay(t *testing.T) {
	storeMiss("github", "a/b")
	if !loadStoredMiss("github", "a/b") {
		t.Fatal("a stored miss was not reused")
	}
	if _, ok := loadStoredLicense("github", "a/b"); ok {
		t.Fatal("a miss must not read as a licence")
	}
	writeStoredLicense(licenseStorePath("github", "c/d\x00miss"), storedLicense{Miss: true, At: 1})
	if loadStoredMiss("github", "c/d") {
		t.Fatal("an expired miss was reused")
	}
}
