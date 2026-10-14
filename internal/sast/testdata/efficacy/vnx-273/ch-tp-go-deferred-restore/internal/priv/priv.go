package priv

import "syscall"

// WithRoot runs fn with the effective uid raised to root.
func WithRoot(fn func() error) error {
	uid := syscall.Getuid()
	if err := syscall.Seteuid(0); err != nil {
		return err
	}
~>	defer syscall.Seteuid(uid)
	return fn()
}
