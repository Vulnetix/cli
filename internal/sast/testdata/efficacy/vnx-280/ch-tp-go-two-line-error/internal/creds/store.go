package creds

import (
	"log"
	"os"
)

// Save writes the token and restricts it to the owner.
func Save(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
~>	err := os.Chmod(path, 0o600)
	if err != nil {
		log.Printf("warning: could not restrict %s: %v", path, err)
	}
	return nil
}

// Lock makes the key read-only for its owner.
func Lock(f *os.File) {
~>	f.Chmod(0400)
}
