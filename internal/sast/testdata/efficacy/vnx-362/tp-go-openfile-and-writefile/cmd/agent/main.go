package main

import (
	"errors"
	"io/fs"
	"os"
)

func writeToken(cfg *Config, token []byte) error {
	_, err := os.Lstat(cfg.TokenPath)
	if errors.Is(err, fs.ErrNotExist) {
~>		return os.WriteFile(cfg.TokenPath, token, 0o600)
	}
	return nil
}

func openLog(name string) (*os.File, error) {
	if _, err := os.Stat(name); err == nil {
		return nil, errors.New("exists")
	}
~>	return os.OpenFile(name,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
}
