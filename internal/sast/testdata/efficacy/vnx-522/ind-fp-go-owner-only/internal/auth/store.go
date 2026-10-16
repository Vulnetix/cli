package auth

import (
	"os"
	"path/filepath"
)

func SaveToken(dir, token string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0o600)
}

func SavePrivateKey(dir string, pem []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, "private_key.pem"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(pem)
	return err
}

func WriteReport(dir string, body []byte) error {
	return os.WriteFile(filepath.Join(dir, "report.html"), body, 0o644)
}

func LoadToken(dir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, "token"))
}
