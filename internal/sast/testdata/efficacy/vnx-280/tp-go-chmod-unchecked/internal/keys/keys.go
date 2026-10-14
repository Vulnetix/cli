package keys

import (
	"log"
	"os"
)

func Save(path string, key []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
~>	f.Chmod(0o600)
	_, err = f.Write(key)
	return err
}

func Lock(path string) {
~>	os.Chmod(path, 0600)
~>	_ = os.Chmod(path+".bak", 0o400)
~>	if err := os.Chmod(path, 0o600); err != nil {
		log.Printf("chmod %s: %v", path, err)
	}
}
