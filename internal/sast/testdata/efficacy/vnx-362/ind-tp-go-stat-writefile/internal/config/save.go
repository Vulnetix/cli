package config

import (
	"fmt"
	"os"
)

// SaveDefault writes the default config unless the operator already has one.
func SaveDefault(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config %s already exists", path)
	}
~>	return os.WriteFile(path, data, 0o600)
}
