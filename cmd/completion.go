package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell autocompletion scripts",
	Long: `Generate shell autocompletion scripts for Vulnetix CLI.

Enable tab completion for commands, subcommands, flags, and flag values.
See the subcommand help for shell-specific installation instructions.`,
}

var completionBashCmd = &cobra.Command{
	Use:                   "bash",
	Short:                 "Generate bash autocompletion script",
	DisableFlagsInUseLine: true,
	Long: `Generate bash autocompletion script for Vulnetix CLI.

To load completions for the current session:

  source <(vulnetix completion bash)

To install completions permanently:

  # Linux
  vulnetix completion bash > ~/.local/share/bash-completion/completions/vulnetix

  # macOS (Homebrew)
  vulnetix completion bash > $(brew --prefix)/etc/bash_completion.d/vulnetix

  # Or append to your .bashrc
  echo 'source <(vulnetix completion bash)' >> ~/.bashrc

Requires bash-completion v2 (bash 4.1+).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenBashCompletionV2(os.Stdout, true)
	},
}

var completionZshCmd = &cobra.Command{
	Use:                   "zsh",
	Short:                 "Generate zsh autocompletion script",
	DisableFlagsInUseLine: true,
	Long: `Generate zsh autocompletion script for Vulnetix CLI.

To load completions for the current session:

  source <(vulnetix completion zsh)

To install completions permanently:

  # Standard zsh
  vulnetix completion zsh > "${fpath[1]}/_vulnetix"

  # Oh My Zsh
  vulnetix completion zsh > ~/.oh-my-zsh/completions/_vulnetix

  # Homebrew (macOS)
  vulnetix completion zsh > $(brew --prefix)/share/zsh/site-functions/_vulnetix

After installing, restart your shell or run: compinit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenZshCompletion(os.Stdout)
	},
}

var completionFishCmd = &cobra.Command{
	Use:                   "fish",
	Short:                 "Generate fish autocompletion script",
	DisableFlagsInUseLine: true,
	Long: `Generate fish autocompletion script for Vulnetix CLI.

To load completions for the current session:

  vulnetix completion fish | source

To install completions permanently:

  vulnetix completion fish > ~/.config/fish/completions/vulnetix.fish

Fish automatically loads completions from ~/.config/fish/completions/.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenFishCompletion(os.Stdout, true)
	},
}

var completionPowershellCmd = &cobra.Command{
	Use:                   "powershell",
	Short:                 "Generate PowerShell autocompletion script",
	DisableFlagsInUseLine: true,
	Long: `Generate PowerShell autocompletion script for Vulnetix CLI.

To load completions for the current session:

  vulnetix completion powershell | Out-String | Invoke-Expression

To install completions permanently:

  vulnetix completion powershell >> $PROFILE

You may need to set the execution policy to allow loading the profile:

  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
	},
}

func init() {
	completionCmd.AddCommand(completionBashCmd)
	completionCmd.AddCommand(completionZshCmd)
	completionCmd.AddCommand(completionFishCmd)
	completionCmd.AddCommand(completionPowershellCmd)
	rootCmd.AddCommand(completionCmd)
}
