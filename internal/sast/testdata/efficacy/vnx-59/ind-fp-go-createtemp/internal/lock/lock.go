package lock

import (
	"os"
	"path/filepath"
)

func Acquire() (*os.File, error) {
	return os.CreateTemp("", "agent-*.lock")
}

func Workdir() (string, error) {
	dir, err := os.MkdirTemp("", "agent-")
	if err != nil {
		return "", err
	}
	f, err := os.Create(filepath.Join(dir, "state.json"))
	if err != nil {
		return "", err
	}
	return dir, f.Close()
}

func Exclusive() (*os.File, error) {
	return os.OpenFile("/tmp/agent.pid", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
