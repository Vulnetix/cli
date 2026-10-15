package store

import (
	"os"
	"path/filepath"
)

func Save(dir string, token []byte, report []byte) error {
	if err := os.WriteFile(filepath.Join(dir, "token.json"), token, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.html"), report, 0644); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "credentials"), os.O_CREATE|os.O_WRONLY, 0o400)
	if err != nil {
		return err
	}
	return f.Close()
}
