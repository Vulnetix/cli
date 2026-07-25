package ghasetup

import (
	"os/exec"
	"strings"
)

// Remote describes the repository's origin.
type Remote struct {
	// URL is the raw origin URL, empty when there is no origin.
	URL string
	// Host is the parsed host ("github.com", "gitlab.com", …), empty when the
	// URL could not be parsed.
	Host string
	// Slug is "owner/repo" when the URL could be parsed.
	Slug string
	// IsGitHub reports whether this is github.com or a GitHub Enterprise host.
	IsGitHub bool
}

// DetectRemote inspects the origin remote of the repository at dir.
//
// A workflow file is only meaningful on GitHub, so the caller warns when this
// is something else. It is a warning rather than an error: mirrors, forks about
// to be pushed to GitHub, and Enterprise hosts with unusual names are all
// legitimate reasons to write the file anyway.
func DetectRemote(dir string) Remote {
	out, err := runGit(dir, "remote", "get-url", "origin")
	if err != nil || out == "" {
		return Remote{}
	}
	return parseRemote(out)
}

func parseRemote(raw string) Remote {
	r := Remote{URL: raw}
	s := strings.TrimSpace(raw)

	switch {
	case strings.HasPrefix(s, "git@"):
		// git@github.com:owner/repo.git
		s = strings.TrimPrefix(s, "git@")
		host, path, ok := strings.Cut(s, ":")
		if !ok {
			return r
		}
		r.Host, r.Slug = host, strings.TrimSuffix(path, ".git")
	case strings.HasPrefix(s, "ssh://"):
		s = strings.TrimPrefix(s, "ssh://")
		s = strings.TrimPrefix(s, "git@")
		host, path, ok := strings.Cut(s, "/")
		if !ok {
			return r
		}
		r.Host = strings.SplitN(host, ":", 2)[0]
		r.Slug = strings.TrimSuffix(path, ".git")
	case strings.Contains(s, "://"):
		_, rest, _ := strings.Cut(s, "://")
		// strip any user:pass@
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		host, path, ok := strings.Cut(rest, "/")
		if !ok {
			return r
		}
		r.Host = strings.SplitN(host, ":", 2)[0]
		r.Slug = strings.TrimSuffix(path, ".git")
	default:
		return r
	}

	h := strings.ToLower(r.Host)
	// A GitHub Enterprise host is conventionally github.<company>.com or
	// git.<company>.com; only the former is safe to assume.
	r.IsGitHub = h == "github.com" || strings.HasPrefix(h, "github.")
	return r
}

// RepoRoot returns the git working-tree root for dir.
func RepoRoot(dir string) (string, error) {
	return runGit(dir, "rev-parse", "--show-toplevel")
}

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
