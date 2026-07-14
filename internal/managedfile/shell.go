package managedfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// KV is one environment variable to persist.
type KV struct {
	Key   string
	Value string
}

// ShellConfigPath returns the rc file for the user's login shell and the dialect
// its assignments must be written in ("fish", "csh", or "sh").
func ShellConfigPath() (path, kind string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	switch filepath.Base(os.Getenv("SHELL")) {
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), "fish", nil
	case "zsh":
		return filepath.Join(home, ".zshrc"), "sh", nil
	case "tcsh":
		return filepath.Join(home, ".tcshrc"), "csh", nil
	case "csh":
		return filepath.Join(home, ".cshrc"), "csh", nil
	case "bash":
		return filepath.Join(home, ".bashrc"), "sh", nil
	default:
		return filepath.Join(home, ".profile"), "sh", nil
	}
}

// EnvBlock renders vars as a managed block in the given shell dialect. A value
// referencing another variable ($FOO) is left unquoted enough to still expand.
func EnvBlock(kind string, m Markers, vars []KV) string {
	lines := make([]string, 0, len(vars))
	for _, v := range vars {
		switch kind {
		case "fish":
			lines = append(lines, "set -gx "+v.Key+" "+v.Value)
		case "csh":
			lines = append(lines, "setenv "+v.Key+" "+v.Value)
		default:
			lines = append(lines, "export "+v.Key+"=\""+v.Value+"\"")
		}
	}
	return Block(m, strings.Join(lines, "\n"))
}

// UpsertBlockFile splices block into the file at path. Unlike UpsertFile it
// never backs up: a shell rc is only ever edited surgically.
func UpsertBlockFile(path, block string, m Markers, dryRun bool) (changed bool, err error) {
	var existing string
	if data, rerr := os.ReadFile(path); rerr == nil {
		existing = string(data)
	} else if !os.IsNotExist(rerr) {
		return false, rerr
	}
	next := Upsert(existing, block, m)
	if existing == next {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveBlockFile strips the managed block from the file at path. The file is
// never deleted, even if the block was all it held — a shell rc belongs to the
// user, not to us.
func RemoveBlockFile(path string, m Markers, dryRun bool) (found bool, err error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	next, changed := Remove(string(data), m)
	if !changed {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		return false, err
	}
	return true, nil
}

// PersistUserEnv sets user-scoped environment variables on Windows, where there
// is no rc file to write. It is a no-op elsewhere.
func PersistUserEnv(vars []KV) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	for _, v := range vars {
		if err := exec.Command("setx", v.Key, v.Value).Run(); err != nil {
			return err
		}
	}
	return nil
}

// ClearUserEnv clears user-scoped environment variables on Windows. Failures are
// ignored: a variable that was never set is not an error worth surfacing.
func ClearUserEnv(keys []string) {
	if runtime.GOOS != "windows" {
		return
	}
	for _, k := range keys {
		_ = exec.Command("setx", k, "").Run()
	}
}
