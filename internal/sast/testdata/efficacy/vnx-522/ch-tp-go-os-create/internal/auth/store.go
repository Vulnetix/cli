package auth

import (
	"os"
	"path/filepath"
)

func SaveToken(dir, token string) error {
~>	f, err := os.Create(filepath.Join(dir, "token"))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(token)
	return err
}

func SaveReport(dir string, body []byte) error {
	f, err := os.Create(filepath.Join(dir, "report.txt"))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(body)
	return err
}
