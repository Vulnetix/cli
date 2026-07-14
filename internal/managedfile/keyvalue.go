package managedfile

import (
	"os"
	"os/exec"
	"strings"
)

// UpsertEnvValues drops every assignment of keys from existing and appends body,
// so the file ends up holding exactly the assignments in body. Used for project
// env files (.env, .envrc, Makefile) where a managed block would be unidiomatic.
func UpsertEnvValues(existing, body string, keys []string) string {
	base := strings.TrimRight(strings.Join(dropEnvLines(strings.Split(existing, "\n"), keys), "\n"), "\n")
	if strings.TrimSpace(base) == "" {
		return body
	}
	return base + "\n" + body
}

// RemoveEnvValues drops every assignment of keys from existing. The bool reports
// whether anything was removed; an empty result means the file held nothing else.
func RemoveEnvValues(existing string, keys []string) (string, bool) {
	kept := dropEnvLines(strings.Split(existing, "\n"), keys)
	if len(kept) == len(strings.Split(existing, "\n")) {
		return existing, false
	}
	out := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if out == "" {
		return "", true
	}
	return out + "\n", true
}

func dropEnvLines(lines, keys []string) []string {
	var kept []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		drop := false
		for _, key := range keys {
			if IsEnvLine(trimmed, key) {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		kept = append(kept, line)
	}
	return kept
}

// IsEnvLine reports whether line assigns key, in any of the assignment forms the
// files we touch use (.env, .envrc/sh, Makefile, csh, fish).
func IsEnvLine(line, key string) bool {
	return strings.HasPrefix(line, key+"=") ||
		strings.HasPrefix(line, "export "+key+"=") ||
		strings.HasPrefix(line, "setenv "+key+" ") ||
		strings.HasPrefix(line, "set -gx "+key+" ")
}

// GitRoot returns the top level of the repository containing the working
// directory, or an error when there is none.
func GitRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// GitIgnored reports whether path is excluded by the repository's ignore rules.
// A file that is not ignored must never receive a literal secret.
func GitIgnored(path string) bool {
	cmd := exec.Command("git", "check-ignore", "-q", path)
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run() == nil
}

// Exists reports whether path is an existing file.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// MaskSecret renders a credential safe to print.
func MaskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
