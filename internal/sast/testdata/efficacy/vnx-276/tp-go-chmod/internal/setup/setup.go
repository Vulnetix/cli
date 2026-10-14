package setup

import (
	"os"
	"os/exec"
)

func Prepare(dir, sock string, f *os.File) error {
~>	if err := os.Chmod(sock, 0777); err != nil {
		return err
	}
~>	if err := f.Chmod(0o666); err != nil {
		return err
	}
~>	if err := os.Chmod(dir, os.ModePerm); err != nil {
		return err
	}
~>	return exec.Command("chmod", "-R", "777", dir).Run()
}
