package main

import (
	"os"

	"github.com/vulnetix/cli/v3/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// Cobra has already printed the message (or Execute deliberately
		// suppressed it for a command that rendered its own). All that is left
		// is the code. Anything that does not name one exits 1, exactly as
		// before.
		os.Exit(cmd.ExitCode(err))
	}
}
