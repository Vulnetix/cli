package files

import (
	"errors"
	"os"
)

func SafeWrite(path string, data []byte) error {
	fi, err := os.Lstat(path)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
~>	return os.WriteFile(path, data, 0o644)
}
