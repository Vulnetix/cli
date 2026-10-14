package store

import "os"

func prepare(dir, file string, data []byte) error {
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	if err := os.WriteFile(file, data, 0666); err != nil {
		return err
	}
	f, err := os.OpenFile(file+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	return f.Close()
}
