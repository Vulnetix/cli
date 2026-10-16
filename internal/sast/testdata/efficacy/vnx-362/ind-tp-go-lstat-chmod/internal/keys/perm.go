package keys

import (
	"log"
	"os"
)

func tightenKey(keyPath string) error {
	info, err := os.Lstat(keyPath)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		log.Printf("fixing permissions on %s", keyPath)
~>		return os.Chmod(keyPath, 0o600)
	}
	return nil
}
