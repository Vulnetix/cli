package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchReleaseByTag(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"tag_name": "v1.2.3",
			"assets": [
				{"name": "tool-linux-amd64", "browser_download_url": "https://example.com/tool-linux-amd64"},
				{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums.txt"}
			]
		}`))
	}))
	defer srv.Close()

	rel, err := FetchReleaseByTag(context.Background(), "tok", srv.URL, "Vulnetix/cli", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/Vulnetix/cli/releases/tags/v1.2.3" {
		t.Errorf("path %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth %q", gotAuth)
	}
	if rel.TagName != "v1.2.3" || len(rel.Assets) != 2 {
		t.Fatalf("release %+v", rel)
	}
}

// A missing release is not an error the caller should die on: a tag can exist
// without a GitHub release, and that release still has evidence worth
// publishing. It just has no download links.
func TestFetchReleaseByTag_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := FetchReleaseByTag(context.Background(), "tok", srv.URL, "Vulnetix/cli", "v9.9.9")
	if err == nil {
		t.Fatal("want an error for a release that does not exist")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should name the status: %v", err)
	}
}

// Projects spell it checksums.txt, SHA256SUMS, tool_checksums.txt. Matching a
// substring case-insensitively covers those without a per-repository input.
func TestAssetMatching(t *testing.T) {
	rel := &Release{Assets: []ReleaseAsset{
		{Name: "tool-linux-amd64"},
		{Name: "CHECKSUMS.txt"},
	}}
	got := rel.AssetMatching("checksums")
	if got == nil || got.Name != "CHECKSUMS.txt" {
		t.Fatalf("got %+v", got)
	}
	if rel.AssetMatching("sbom") != nil {
		t.Error("want nil when nothing matches")
	}
}

func TestDownloadAsset(t *testing.T) {
	const body = "b9f62ff7  tool-linux-amd64\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path, err := DownloadAsset(context.Background(), "tok",
		ReleaseAsset{Name: "checksums.txt", BrowserDownloadURL: srv.URL}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("wrote outside the destination: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != body {
		t.Errorf("content %q", b)
	}
}

// An asset name is attacker-influenced in the general case. It must not be able
// to escape the destination directory or write outside it.
func TestDownloadAsset_RejectsPathTraversal(t *testing.T) {
	testCases := []string{
		"../escaped.txt",
		"..",
		".",
		"",
		"/etc/passwd",
		"sub/file.txt",
		"a\\b.txt",
	}

	for _, name := range testCases {
		t.Run(name, func(t *testing.T) {
			serverWasCalled := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serverWasCalled = true
				_, _ = w.Write([]byte("x"))
			}))
			defer srv.Close()

			dir := t.TempDir()
			path, err := DownloadAsset(context.Background(), "tok",
				ReleaseAsset{Name: name, BrowserDownloadURL: srv.URL}, dir)

			// Rejected names must return an error and must not trigger an HTTP request.
			if err == nil {
				t.Fatalf("want an error for asset name %q", name)
			}
			if serverWasCalled {
				t.Errorf("server was called for rejected asset name %q; guard must reject before HTTP", name)
			}
			if path != "" {
				t.Errorf("unexpected path returned for error case: %q", path)
			}
		})
	}
}
