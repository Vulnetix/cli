package setup

import (
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// InstallHelper marks the helper binary setuid.
func InstallHelper(helper string) error {
~>	if err := os.Chmod(helper, 0o755|os.ModeSetuid); err != nil {
		return err
	}
~>	if err := unix.Fchmodat(unix.AT_FDCWD, helper, 0o4755, 0); err != nil {
		return err
	}
~>	out, err := exec.Command("chmod", "u+s", helper).CombinedOutput()
	_ = out
	return err
}
