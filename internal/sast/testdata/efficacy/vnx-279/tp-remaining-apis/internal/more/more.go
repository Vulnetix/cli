package more

import "golang.org/x/sys/unix"

func More(bin string) error {
~>	return unix.Chmod(bin, unix.S_ISUID|0o755)
}
