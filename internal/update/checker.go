package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const releasesURL = "https://api.github.com/repos/Vulnetix/cli/releases/latest"

// Release represents the relevant fields from a GitHub release.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a downloadable file from a GitHub release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckLatest fetches the latest release from GitHub and returns it.
func CheckLatest() (*Release, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vulnetix-cli")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	return &release, nil
}

// FindAsset returns the download URL for the current OS/arch from the release assets.
func FindAsset(release *Release) string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	suffix := ""
	if goos == "windows" {
		suffix = ".exe"
	}

	// Try exact match first: vulnetix-linux-amd64, vulnetix-darwin-arm64.exe, etc.
	target := fmt.Sprintf("vulnetix-%s-%s%s", goos, goarch, suffix)
	for _, a := range release.Assets {
		if strings.EqualFold(a.Name, target) {
			return a.BrowserDownloadURL
		}
	}

	return ""
}
