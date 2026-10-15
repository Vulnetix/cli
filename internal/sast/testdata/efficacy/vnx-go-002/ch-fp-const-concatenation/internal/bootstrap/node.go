package bootstrap

import "os/exec"

const (
	prelude       = "set -euo pipefail\n"
	installScript = "apt-get update && apt-get install -y ca-certificates curl\n"
	cleanup       = "rm -rf /var/lib/apt/lists/*\n"
)

// Prepare runs the fixed provisioning script; every piece is a constant
// declared above.
func Prepare() error {
	return exec.Command("bash", "-c", prelude+installScript+cleanup).Run()
}
