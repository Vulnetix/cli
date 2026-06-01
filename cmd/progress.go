package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
)

var commandProgressWrapped bool

func installCommandProgress() {
	if commandProgressWrapped {
		return
	}
	commandProgressWrapped = true
	wrapVDBProgress(vdbCmd)
}

func wrapVDBProgress(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	if cmd.RunE != nil {
		original := cmd.RunE
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			dctx := display.FromCommand(cmd)
			title := "VDB query"
			if name := vdbProgressName(cmd); name != "" {
				title = name
			}
			progress := dctx.Progress(title, 2)
			progress.Update(1, "Executing VDB request")
			err := original(cmd, args)
			if err != nil {
				progress.Fail("VDB request failed")
				return err
			}
			progress.Complete("VDB response handled")
			return nil
		}
	}
	for _, child := range cmd.Commands() {
		wrapVDBProgress(child)
	}
}

func vdbProgressName(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	path := cmd.CommandPath()
	if path == "" {
		return ""
	}
	path = strings.TrimSpace(strings.TrimPrefix(path, "vulnetix "))
	path = strings.TrimSpace(strings.TrimPrefix(path, "vdb "))
	if path == "" {
		return ""
	}
	return fmt.Sprintf("VDB %s", path)
}
