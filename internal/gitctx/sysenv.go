package gitctx

import (
	"os"
	"os/user"
	"runtime"
)

// SystemInfo captures host and process-environment context at scan time.
type SystemInfo struct {
	Hostname string `json:"hostname,omitempty"`
	// Shell is the value of $SHELL (Linux/macOS) or %ComSpec% (Windows).
	Shell    string `json:"shell,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Username string `json:"username,omitempty"`
}

// CollectSystemInfo gathers host and environment metadata.
// It never returns nil; individual fields may be empty when they cannot be read.
func CollectSystemInfo() *SystemInfo {
	info := &SystemInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	// Prefer $SHELL; fall back to %ComSpec% on Windows.
	if s := os.Getenv("SHELL"); s != "" {
		info.Shell = s
	} else if s := os.Getenv("ComSpec"); s != "" {
		info.Shell = s
	}

	if u, err := user.Current(); err == nil {
		info.Username = u.Username
	}

	return info
}
