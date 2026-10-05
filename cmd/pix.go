package cmd

import (
	"github.com/spf13/cobra"
)

// pixCmd is the `vulnetix pix` shortcut for the Pix AI coding assistant plugin.
// It mirrors the `vulnetix skills` command set but uses the product name users
// see in the assistant marketplace, so `vulnetix pix install` is the fastest
// way to install the Vulnetix skills into that plugin.
var pixCmd = &cobra.Command{
	Use:   "pix",
	Short: "Manage the Pix AI coding assistant plugin",
	Long: "Manage the Pix AI coding assistant plugin and its Vulnetix skills.\n\n" +
		"This is a convenience alias for the 'vulnetix skills' commands that target " +
		"Pix. 'vulnetix pix install' installs the plugin's skills using the same " +
		"best-effort detection (npx, claude, gh) as 'vulnetix skills install'.",
}

var pixInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Vulnetix skills into Pix",
	Long: "Install Vulnetix skills into the Pix AI coding assistant.\n\n" +
		"This delegates to the skills installer, so it supports the same --agent " +
		"and --skill flags as 'vulnetix skills install'.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return skillsInstallCmd.RunE(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(pixCmd)

	pixInstallCmd.Flags().StringVar(&skillsAgent, "agent", "", "Target a specific agent (e.g., claude-code, codex, pi)")
	pixInstallCmd.Flags().StringVar(&skillsSkill, "skill", "", "Target a specific skill (e.g., fix, sast-scan)")
	pixCmd.AddCommand(pixInstallCmd)
}
