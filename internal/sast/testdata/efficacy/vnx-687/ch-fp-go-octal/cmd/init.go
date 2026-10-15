package main

import "os"

func setup(dir string, data []byte) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/state", data, os.FileMode(0o644)); err != nil {
		return err
	}
	return os.Chmod(dir, 0)
}
