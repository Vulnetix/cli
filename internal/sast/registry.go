package sast

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultRegistry is the base URL used when --rule-registry is not set.
const DefaultRegistry = "https://github.com"

// RuleRef identifies an external rule repository by org and repo name.
type RuleRef struct {
	Org  string
	Repo string
}

// ParseRuleRef parses a "org/repo" string from a --rule flag value.
func ParseRuleRef(arg string) (RuleRef, error) {
	parts := strings.SplitN(strings.TrimSpace(arg), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return RuleRef{}, fmt.Errorf("invalid rule reference %q: expected org/repo", arg)
	}
	return RuleRef{Org: parts[0], Repo: parts[1]}, nil
}

// ResolveURL builds the git clone URL from a registry base URL and rule reference.
func ResolveURL(registry string, ref RuleRef) string {
	return strings.TrimRight(registry, "/") + "/" + ref.Org + "/" + ref.Repo
}

// CacheDir returns the OS-native cache directory for a rule repository.
//
//	Linux:   ~/.cache/vulnetix/rules/<org>/<repo>/
//	macOS:   ~/Library/Caches/vulnetix/rules/<org>/<repo>/
//	Windows: %LOCALAPPDATA%\vulnetix\rules\<org>\<repo>\
func CacheDir(ref RuleRef) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("cache dir: %w", err)
	}
	return filepath.Join(base, "vulnetix", "rules", ref.Org, ref.Repo), nil
}
