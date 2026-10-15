package login

import (
	"fmt"
	"os"
	"path/filepath"
)

func SaveNetrc(home, host, user, password string) error {
	data := fmt.Sprintf("machine %s login %s password %s\n", host, user, password)
~>	return os.WriteFile(filepath.Join(home, ".netrc"), []byte(data), 0644)
}

func SaveToken(dir, accessToken string) error {
~>	f, err := os.OpenFile(filepath.Join(dir, "token.json"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0664)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(accessToken)
	return err
}
