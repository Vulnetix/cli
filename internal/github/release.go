package github

// Reading a GitHub release, for the one thing `tea release` needs from it: the
// checksums manifest the release already publishes. Taking the digests from
// that file rather than recomputing them is what makes the checksum a consumer
// reads through TEA the same string the project published.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// maxAssetBytes caps a manifest download. A checksums file is a few kilobytes;
// anything near this is not the file we asked for.
const maxAssetBytes = 8 << 20

type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type Release struct {
	TagName string         `json:"tag_name"`
	Assets  []ReleaseAsset `json:"assets"`
}

// FetchReleaseByTag reads one release by its tag.
//
// apiURL is a parameter rather than a constant because GitHub Enterprise serves
// a different host, and guessing github.com there would read the wrong instance.
func FetchReleaseByTag(ctx context.Context, token, apiURL, repository, tag string) (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s",
		strings.TrimRight(apiURL, "/"), repository, tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d %s", url, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAssetBytes)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &rel, nil
}

// AssetMatching finds the first asset whose name contains substr, ignoring case.
//
// Substring rather than exact match because projects spell the same file
// checksums.txt, SHA256SUMS and tool_checksums.txt, and requiring each
// repository to declare which would be a per-repository input for a question
// the release itself already answers.
func (r *Release) AssetMatching(substr string) *ReleaseAsset {
	want := strings.ToLower(substr)
	for i := range r.Assets {
		if strings.Contains(strings.ToLower(r.Assets[i].Name), want) {
			return &r.Assets[i]
		}
	}
	return nil
}

// DownloadAsset writes an asset into destDir and returns its path.
func DownloadAsset(ctx context.Context, token string, a ReleaseAsset, destDir string) (string, error) {
	// The name comes from the API, so it is not ours. A plain file name is the
	// only thing we accept; anything else would escape destDir. All these checks
	// must happen before any HTTP request is made.
	if a.Name == "" || a.Name == "." || a.Name == ".." || a.Name != filepath.Base(a.Name) || strings.ContainsAny(a.Name, `/\`) {
		return "", fmt.Errorf("refusing asset name %q: it is not a plain file name", a.Name)
	}

	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return "", err
	}

	path := filepath.Join(absDestDir, a.Name)
	relPath, err := filepath.Rel(absDestDir, path)
	if err != nil {
		return "", err
	}

	// Belt-and-braces: verify the resolved path does not escape. This guards
	// against filepath.Join doing something unexpected.
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing asset name %q: it is not a plain file name", a.Name)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %d %s", a.BrowserDownloadURL, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, io.LimitReader(resp.Body, maxAssetBytes)); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// ReleaseInfo is a release as the write side needs it.
type ReleaseInfo struct {
	ID        int64        `json:"id"`
	TagName   string       `json:"tag_name"`
	UploadURL string       `json:"upload_url"`
	HTMLURL   string       `json:"html_url"`
	Draft     bool         `json:"draft"`
	Assets    []AssetEntry `json:"assets"`
}

// AssetEntry is an uploaded release asset.
type AssetEntry struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// EnsureRelease returns the release for tag. When there is none it creates
// it as a draft if create is set, so nothing is published by accident, and
// otherwise returns the 404. Needs contents: write.
func (c *Client) EnsureRelease(ctx context.Context, repo, tag string, create bool) (*ReleaseInfo, bool, error) {
	var rel ReleaseInfo
	_, err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/releases/tags/%s", repo, url.PathEscape(tag)), nil, &rel)
	if err == nil {
		return &rel, false, nil
	}
	if !IsStatus(err, http.StatusNotFound) || !create {
		return nil, false, err
	}
	body := map[string]any{"tag_name": tag, "name": tag, "draft": true}
	if _, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/releases", repo), body, &rel); err != nil {
		return nil, false, err
	}
	return &rel, true, nil
}

// UploadAsset uploads the file at path to the release under name. An asset
// of the same name is replaced when clobber is set, and is an error
// otherwise, since GitHub refuses a duplicate name.
func (c *Client) UploadAsset(ctx context.Context, repo string, rel *ReleaseInfo, path, name string, clobber bool) (*AssetEntry, error) {
	if name == "" {
		name = filepath.Base(path)
	}
	for _, a := range rel.Assets {
		if a.Name != name {
			continue
		}
		if !clobber {
			return nil, fmt.Errorf("release %s already has an asset named %s", rel.TagName, name)
		}
		if _, err := c.Do(ctx, http.MethodDelete, fmt.Sprintf("/repos/%s/releases/assets/%d", repo, a.ID), nil, nil); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return nil, err
	}
	// upload_url is a URI template ending in {?name,label}; it carries the
	// uploads host, which differs on GitHub Enterprise Server.
	base := rel.UploadURL
	if i := strings.Index(base, "{"); i >= 0 {
		base = base[:i]
	}
	if base == "" {
		return nil, fmt.Errorf("release %s has no upload URL", rel.TagName)
	}
	u := base + "?name=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, file)
	if err != nil {
		return nil, err
	}
	req.ContentLength = st.Size()
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	c.Calls++
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, &APIError{Method: http.MethodPost, Path: u, Status: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}
	var a AssetEntry
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return nil, err
	}
	return &a, nil
}
