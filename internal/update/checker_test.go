package update

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckLatest_Success(t *testing.T) {
	want := Release{
		TagName: "v1.2.3",
		Assets: []Asset{
			{Name: "vulnetix-linux-amd64", BrowserDownloadURL: "https://example.com/linux"},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
		assert.Equal(t, "vulnetix-cli", r.Header.Get("User-Agent"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"tag_name":"v1.2.3","assets":[{"name":"vulnetix-linux-amd64","browser_download_url":"https://example.com/linux"}]}`))
		require.NoError(t, err)
	}))
	defer ts.Close()

	orig := releaseURL
	releaseURL = ts.URL
	defer func() { releaseURL = orig }()

	release, err := CheckLatest()
	require.NoError(t, err)
	assert.Equal(t, &want, release)
}

func TestCheckLatest_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	orig := releaseURL
	releaseURL = ts.URL
	defer func() { releaseURL = orig }()

	_, err := CheckLatest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestCheckLatest_InternalServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	orig := releaseURL
	releaseURL = ts.URL
	defer func() { releaseURL = orig }()

	_, err := CheckLatest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestCheckLatest_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{`))
	}))
	defer ts.Close()

	orig := releaseURL
	releaseURL = ts.URL
	defer func() { releaseURL = orig }()

	_, err := CheckLatest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse release info")
}

func TestFindAsset_LinuxAMD64(t *testing.T) {
	origOS, origArch := goos, goarch
	goos, goarch = "linux", "amd64"
	defer func() { goos, goarch = origOS, origArch }()

	release := &Release{
		Assets: []Asset{
			{Name: "vulnetix-linux-amd64", BrowserDownloadURL: "https://example.com/linux"},
			{Name: "vulnetix-darwin-arm64", BrowserDownloadURL: "https://example.com/darwin"},
		},
	}

	assert.Equal(t, "https://example.com/linux", FindAsset(release))
}

func TestFindAsset_WindowsAMD64(t *testing.T) {
	origOS, origArch := goos, goarch
	goos, goarch = "windows", "amd64"
	defer func() { goos, goarch = origOS, origArch }()

	release := &Release{
		Assets: []Asset{
			{Name: "vulnetix-linux-amd64", BrowserDownloadURL: "https://example.com/linux"},
			{Name: "vulnetix-windows-amd64.exe", BrowserDownloadURL: "https://example.com/windows"},
		},
	}

	assert.Equal(t, "https://example.com/windows", FindAsset(release))
}

func TestFindAsset_NoMatch(t *testing.T) {
	origOS, origArch := goos, goarch
	goos, goarch = "freebsd", "amd64"
	defer func() { goos, goarch = origOS, origArch }()

	release := &Release{
		Assets: []Asset{
			{Name: "vulnetix-linux-amd64", BrowserDownloadURL: "https://example.com/linux"},
		},
	}

	assert.Empty(t, FindAsset(release))
}
