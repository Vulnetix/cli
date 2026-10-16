package out

import "os"

func Save(p string, b []byte) error {
	if err := os.MkdirAll("out", 0o777); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0666)
}
