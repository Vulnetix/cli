package jobs

import (
	"context"
	"os/exec"
)

func Archive(ctx context.Context, dir string) error {
	script := "tar czf /backup/out.tgz " + dir
~>	return exec.CommandContext(ctx, "bash", "-c", script).Run()
}
