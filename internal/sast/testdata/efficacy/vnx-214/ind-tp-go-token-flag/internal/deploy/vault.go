package deploy

import (
	"context"
	"os/exec"
)

func readSecret(ctx context.Context, addr, token, path string) ([]byte, error) {
~>	cmd := exec.CommandContext(ctx, "vault", "kv", "get", "-address="+addr, "--token="+token, "-format=json", path)
	return cmd.Output()
}
