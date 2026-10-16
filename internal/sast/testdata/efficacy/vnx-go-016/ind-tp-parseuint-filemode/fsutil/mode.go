package fsutil

import (
	"os"
	"strconv"
)

func Chmod(path, mode string) error {
	m, err := strconv.ParseUint(mode, 8, 64)
	if err != nil {
		return err
	}
~>	return os.Chmod(path, os.FileMode(m))
}

func Limit(s string) int64 {
	mb, _ := strconv.ParseUint(s, 10, 64)
~>	return int64(mb)
}
