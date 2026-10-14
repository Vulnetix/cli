package secrets

import (
	"errors"
	"io/fs"
	"os"
)

// Protect restricts path to its owner, unless the process may not.
func Protect(path string) error {
~>	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, fs.ErrPermission) {
		return err
	}
	return nil
}

// ProtectKey is the same with the older helper.
func ProtectKey(path string) error {
~>	err := os.Chmod(path, 0400)
	if err != nil && !os.IsPermission(err) {
		return err
	}
	return nil
}
