package cache

import (
	"fmt"
	"os"
)

// Dir creates the cache directory or explains why it cannot.
func Dir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if os.IsPermission(err) {
			return "", fmt.Errorf("cannot create %s; set AGENT_CACHE, for example to /tmp/agent", dir)
		}
		return "", err
	}
	return dir, nil
}
