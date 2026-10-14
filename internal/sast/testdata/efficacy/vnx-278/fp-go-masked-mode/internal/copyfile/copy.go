package copyfile

import "os"

func Copy(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, fi.Mode())
}
