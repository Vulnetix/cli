package copyfile

import (
	"io"
	"os"
)

func Copy(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return err
	}
	in, err := os.OpenFile(src, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return err
}
