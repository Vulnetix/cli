package install

import (
	"os"
	"os/exec"
	"syscall"
)

func Helper(bin string, f *os.File, fi os.FileInfo) error {
~>	if err := os.Chmod(bin, os.ModeSetuid|0o755); err != nil {
		return err
	}
~>	if err := f.Chmod(fi.Mode() | os.ModeSetuid); err != nil {
		return err
	}
~>	if err := syscall.Chmod(bin, 0o4755); err != nil {
		return err
	}
~>	return exec.Command("chmod", "u+s", bin).Run()
}
