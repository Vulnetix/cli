package cache

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Dir returns the cache directory, creating it.
func Dir() string {
	dir := "/var/cache/agent"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if os.IsPermission(err) {
~>			dir = os.TempDir()
		}
	}
	return dir
}

// SocketPath returns where the control socket lives.
func SocketPath(name string) (string, error) {
	p := filepath.Join("/run/agent", name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		if errors.Is(err, fs.ErrPermission) {
~>			return filepath.Join("/tmp", name), nil
		}
		return "", err
	}
	return p, nil
}
