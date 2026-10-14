package install

import (
	"context"
	"fmt"
	"os/exec"
)

func Fetch(ctx context.Context, url, dest string) error {
~>	cmd := exec.CommandContext(
		ctx,
		"sh", "-c",
		fmt.Sprintf("curl -fsSL %s | tar xz -C %s", url, dest),
	)
	return cmd.Run()
}

func ListWindows(path string) ([]byte, error) {
~>	return exec.Command("cmd.exe", "/C", "dir "+path).Output()
}

func ItemWindows(p string) ([]byte, error) {
~>	return exec.Command("powershell", "-Command", fmt.Sprintf("Get-Item '%s'", p)).Output()
}

func LoginShell(user string) error {
~>	return exec.Command("bash", "-lc", "id "+user).Run()
}
