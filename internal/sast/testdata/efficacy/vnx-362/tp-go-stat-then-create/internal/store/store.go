package store

import "os"

func Init(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
~>		f, err := os.Create(path)
		if err != nil {
			return err
		}
		return f.Close()
	}
	return nil
}
