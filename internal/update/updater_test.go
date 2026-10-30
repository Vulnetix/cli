package update

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stubExecutable(path string, err error) func() {
	orig := executablePath
	executablePath = func() (string, error) { return path, err }
	return func() { executablePath = orig }
}

func mustWriteExe(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, []byte("stub"), 0755))
}

// realTempDir returns t.TempDir() with symlinks resolved. DetectInstallMethod
// resolves the executable's path, so on macOS, where the temp dir sits under the
// /var -> /private/var symlink, an unresolved dir would never match.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return dir
}

// setHome points os.UserHomeDir at dir on every platform: it reads HOME on Unix
// and USERPROFILE on Windows.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func TestDetectInstallMethod_SourceBuildDev(t *testing.T) {
	assert.Equal(t, MethodSourceBuild, DetectInstallMethod("1.2.3-dev", "abc1234"))
}

func TestDetectInstallMethod_SourceBuildUnknownCommit(t *testing.T) {
	assert.Equal(t, MethodSourceBuild, DetectInstallMethod("1.2.3", "unknown"))
}

func TestDetectInstallMethod_GoInstallGOBIN(t *testing.T) {
	dir := realTempDir(t)
	exe := filepath.Join(dir, "vulnetix")
	mustWriteExe(t, exe)
	t.Setenv("GOBIN", dir)
	t.Setenv("GOPATH", "")
	setHome(t, realTempDir(t))
	cleanup := stubExecutable(exe, nil)
	defer cleanup()

	assert.Equal(t, MethodGoInstall, DetectInstallMethod("1.2.3", "abc1234"))
}

func TestDetectInstallMethod_GoInstallGOPATHBin(t *testing.T) {
	gopath := realTempDir(t)
	exe := filepath.Join(gopath, "bin", "vulnetix")
	mustWriteExe(t, exe)
	t.Setenv("GOBIN", "")
	t.Setenv("GOPATH", gopath)
	setHome(t, realTempDir(t))
	cleanup := stubExecutable(exe, nil)
	defer cleanup()

	assert.Equal(t, MethodGoInstall, DetectInstallMethod("1.2.3", "abc1234"))
}

func TestDetectInstallMethod_GoInstallDefaultHome(t *testing.T) {
	home := realTempDir(t)
	exe := filepath.Join(home, "go", "bin", "vulnetix")
	mustWriteExe(t, exe)
	t.Setenv("GOBIN", "")
	t.Setenv("GOPATH", "")
	setHome(t, home)
	cleanup := stubExecutable(exe, nil)
	defer cleanup()

	assert.Equal(t, MethodGoInstall, DetectInstallMethod("1.2.3", "abc1234"))
}

func TestDetectInstallMethod_PrebuiltFallback(t *testing.T) {
	home := realTempDir(t)
	dir := realTempDir(t)
	exe := filepath.Join(dir, "vulnetix")
	mustWriteExe(t, exe)
	t.Setenv("GOBIN", "")
	t.Setenv("GOPATH", "")
	setHome(t, home)
	cleanup := stubExecutable(exe, nil)
	defer cleanup()

	assert.Equal(t, MethodPrebuilt, DetectInstallMethod("1.2.3", "abc1234"))
}

func TestDetectInstallMethod_PrebuiltExecutableError(t *testing.T) {
	t.Setenv("GOBIN", "")
	t.Setenv("GOPATH", "")
	setHome(t, realTempDir(t))
	cleanup := stubExecutable("", errors.New("no exe"))
	defer cleanup()

	assert.Equal(t, MethodPrebuilt, DetectInstallMethod("1.2.3", "abc1234"))
}

func TestUpdate_SourceBuild(t *testing.T) {
	err := Update("1.2.3-dev", "abc1234")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "built from source")
}

func TestUpdate_GoInstall(t *testing.T) {
	dir := realTempDir(t)
	exe := filepath.Join(dir, "vulnetix")
	mustWriteExe(t, exe)
	t.Setenv("GOBIN", dir)
	t.Setenv("GOPATH", "")
	setHome(t, realTempDir(t))
	cleanup := stubExecutable(exe, nil)
	defer cleanup()

	origRunner := goInstallRunner
	called := false
	goInstallRunner = func() error {
		called = true
		return errors.New("mock go install")
	}
	defer func() { goInstallRunner = origRunner }()

	err := Update("1.2.3", "abc1234")
	require.Error(t, err)
	assert.Equal(t, "mock go install", err.Error())
	assert.True(t, called)
}

func TestUpdate_UnknownMethod(t *testing.T) {
	orig := detectInstallMethod
	detectInstallMethod = func(string, string) InstallMethod { return InstallMethod(99) }
	defer func() { detectInstallMethod = orig }()

	err := Update("1.2.3", "abc1234")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown install method")
}

func TestUpdatePrebuilt_Success(t *testing.T) {
	exeDir := t.TempDir()
	exe := filepath.Join(exeDir, "vulnetix")
	require.NoError(t, os.WriteFile(exe, []byte("old"), 0755))

	cleanup := stubExecutable(exe, nil)
	defer cleanup()

	origGoos, origGoarch := goos, goarch
	goos, goarch = "linux", "amd64"
	defer func() { goos, goarch = origGoos, origGoarch }()

	asset := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new binary"))
	}))
	defer asset.Close()

	release := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"tag_name":"v1.3.0","assets":[{"name":"vulnetix-linux-amd64","browser_download_url":%q}]}`, asset.URL)
	}))
	defer release.Close()

	origReleaseURL := releaseURL
	releaseURL = release.URL
	defer func() { releaseURL = origReleaseURL }()

	require.NoError(t, updatePrebuilt())

	data, err := os.ReadFile(exe)
	require.NoError(t, err)
	assert.Equal(t, "new binary", string(data))

	// The temp file should be gone and the old binary should not linger.
	matches, err := filepath.Glob(filepath.Join(exeDir, "vulnetix-update-*"))
	require.NoError(t, err)
	assert.Empty(t, matches)
	assert.NoFileExists(t, exe+".old", "only Windows moves the old binary aside")
}

func TestUpdatePrebuilt_WindowsRename(t *testing.T) {
	exeDir := t.TempDir()
	exe := filepath.Join(exeDir, "vulnetix.exe")
	require.NoError(t, os.WriteFile(exe, []byte("old"), 0755))

	cleanup := stubExecutable(exe, nil)
	defer cleanup()

	origGoos, origGoarch := goos, goarch
	goos, goarch = "windows", "amd64"
	defer func() { goos, goarch = origGoos, origGoarch }()

	asset := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new binary"))
	}))
	defer asset.Close()

	release := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"tag_name":"v1.3.0","assets":[{"name":"vulnetix-windows-amd64.exe","browser_download_url":%q}]}`, asset.URL)
	}))
	defer release.Close()

	origReleaseURL := releaseURL
	releaseURL = release.URL
	defer func() { releaseURL = origReleaseURL }()

	require.NoError(t, updatePrebuilt())

	data, err := os.ReadFile(exe)
	require.NoError(t, err)
	assert.Equal(t, "new binary", string(data))

	// The running binary must have been moved aside before the replace, since
	// Windows cannot overwrite an executable in use.
	old, err := os.ReadFile(exe + ".old")
	require.NoError(t, err, "the old binary was not moved aside")
	assert.Equal(t, "old", string(old))
}
