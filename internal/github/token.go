package github

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

// ErrNoToken is returned when no GitHub token can be found.
var ErrNoToken = errors.New("no GitHub token found: set GITHUB_TOKEN or run 'gh auth login'")

// ResolveToken finds a GitHub token: GITHUB_TOKEN, then GH_TOKEN (the gh CLI's
// convention), then `gh auth token`. source names where it came from
// ("env:GITHUB_TOKEN", "env:GH_TOKEN", "gh-cli") for status output; the token
// itself is never printed.
func ResolveToken() (token, source string, err error) {
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t, "env:GITHUB_TOKEN", nil
	}
	if t := strings.TrimSpace(os.Getenv("GH_TOKEN")); t != "" {
		return t, "env:GH_TOKEN", nil
	}
	if out, err := exec.Command("gh", "auth", "token").Output(); err == nil {
		if t := strings.TrimSpace(string(out)); t != "" {
			return t, "gh-cli", nil
		}
	}
	return "", "", ErrNoToken
}
