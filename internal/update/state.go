package update

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const updateCheckCooldown = 24 * time.Hour

// stateDir returns ~/.vulnetix/state, creating it if needed.
func stateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".vulnetix", "state")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// ShouldCheckForUpdate returns true if the last update check was more than
// 24 hours ago (or if the state file doesn't exist).
func ShouldCheckForUpdate() bool {
	dir, err := stateDir()
	if err != nil {
		return true
	}
	data, err := os.ReadFile(filepath.Join(dir, "last-update-check"))
	if err != nil {
		return true
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return true
	}
	return time.Since(time.Unix(ts, 0)) >= updateCheckCooldown
}

// RecordUpdateCheck writes the current timestamp to the state file.
func RecordUpdateCheck() {
	dir, err := stateDir()
	if err != nil {
		return
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	_ = os.WriteFile(filepath.Join(dir, "last-update-check"), []byte(ts), 0600)
}
