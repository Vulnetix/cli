package main

import (
	"os"

	"github.com/vulnetix/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// Cobra already prints the error, so we just exit
		os.Exit(1)
	}
}
