package lock

import (
	"os"
	"path/filepath"
)

// Acquire creates the agent's lock file.
func Acquire() (*os.File, error) {
	lock := filepath.Join(os.TempDir(), "agent.lock")
~>	return os.Create(lock)
}
