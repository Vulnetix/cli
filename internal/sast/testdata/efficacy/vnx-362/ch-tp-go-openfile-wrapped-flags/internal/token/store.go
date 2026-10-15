package token

import (
	"errors"
	"os"
)

func Save(path string, tok []byte) error {
	if _, err := os.Stat(path); err == nil {
		return errors.New("token already present")
	}
~>	f, err := os.OpenFile(path,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(tok)
	return err
}
