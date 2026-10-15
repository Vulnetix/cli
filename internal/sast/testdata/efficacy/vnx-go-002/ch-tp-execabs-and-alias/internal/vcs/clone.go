package vcs

import (
	"context"
	"fmt"
	osexec "os/exec"

	"golang.org/x/sys/execabs"
)

// Clone fetches a repository named in a webhook payload.
func Clone(ctx context.Context, repo, dir string) error {
~>	cmd := execabs.CommandContext(ctx, "sh", "-c", "git clone --depth 1 "+repo+" "+dir)
	return cmd.Run()
}

func Checkout(ref string) ([]byte, error) {
~>	return osexec.Command("bash", "-c", fmt.Sprintf("git checkout %s && git submodule update", ref)).CombinedOutput()
}
