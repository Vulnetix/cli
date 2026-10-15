package main

import "os"

func setup(dir string, data []byte) error {
~>	if err := os.MkdirAll(dir, 755); err != nil {
		return err
	}
~>	return os.WriteFile(dir+"/state", data, 644)
}
