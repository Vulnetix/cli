package files

import "os"

func Write(dir *os.Root, name string, data []byte) error {
	fi, err := os.Lstat(name)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return os.ErrInvalid
	}
	f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
