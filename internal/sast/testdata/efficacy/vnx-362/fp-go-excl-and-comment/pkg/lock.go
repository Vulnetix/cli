package pkg

import "os"

// Do not write: if _, err := os.Stat(p); err != nil { os.Create(p) }
func Acquire(p string) (*os.File, error) {
	if _, err := os.Stat(p); err == nil {
		return nil, os.ErrExist
	}
	return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func Other(a, b string) error {
	if _, err := os.Stat(a); err != nil {
		return err
	}
	return os.WriteFile(b, nil, 0o600)
}
