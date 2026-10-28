//go:build unix

package execwatch

import (
	"os"
	"syscall"
)

// inode identifies the file currently at path, so a rotation (a new file under
// the same name) is noticed. 0 when it cannot be read.
func inode(path string) uint64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}

	return 0
}
