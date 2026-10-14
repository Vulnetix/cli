package creds

import (
	"fmt"
	"log"
	"os"
)

func saveOK(path, binPath, logPath string, data []byte) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict %s: %w", path, err)
	}
	err := os.Chmod(path, 0o600)
	if err != nil {
		return err
	}
	os.Chmod(binPath, 0o755)
	_ = os.Chmod(logPath, 0o644)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		log.Printf("write: %v", err)
	}
	return nil
}
