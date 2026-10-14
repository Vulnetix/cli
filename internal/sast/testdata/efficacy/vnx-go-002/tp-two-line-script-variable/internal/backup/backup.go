package backup

import (
	"context"
	"fmt"
	"os/exec"
)

// Archive formats a whole shell command line, then hands it to sh -c: a
// name such as "x; rm -rf /" runs as a second command.
func Archive(dir, name string) error {
	script := fmt.Sprintf("tar czf /backups/%s.tgz %s", name, dir)
~>	return exec.Command("/bin/sh", "-c", script).Run()
}

func Clone(ctx context.Context, repo, dest string) error {
	cmdline := "git clone --depth 1 " + repo + " " + dest
	cmd := exec.Command("true")
	if ctx != nil {
~>		cmd = exec.CommandContext(ctx, "bash", "-c", cmdline)
	}
	return cmd.Run()
}
