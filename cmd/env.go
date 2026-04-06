package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/config"
	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/scan"
)

var envOutput string

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Display current environment context",
	Long: `Show structured metadata about the current environment including
platform detection, git repository info, detected package managers, and memory status.

The Claude Code Plugin captures this output for its own use.

Examples:
  vulnetix env                  # human-readable output
  vulnetix env --output json    # JSON output for machine consumption`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		envData := gatherFullEnvironment(cwd)

		if envOutput == "json" {
			data, err := json.MarshalIndent(envData, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal env data: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		printEnvHumanReadable(envData)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.Flags().StringVarP(&envOutput, "output", "o", "", "Output format (json)")
}

type envCLIInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

type envGitInfo struct {
	Branch        string   `json:"branch,omitempty"`
	Commit        string   `json:"commit,omitempty"`
	RemoteURLs    []string `json:"remote_urls,omitempty"`
	IsDirty       bool     `json:"is_dirty"`
	IsWorktree    bool     `json:"is_worktree"`
	CommitAuthor  string   `json:"commit_author,omitempty"`
	CommitEmail   string   `json:"commit_email,omitempty"`
	CommitMessage string   `json:"commit_message,omitempty"`
	RepoRoot      string   `json:"repo_root,omitempty"`
}

type envPackageManagerInfo struct {
	Ecosystem string `json:"ecosystem"`
	Language  string `json:"language"`
	Manifest  string `json:"manifest"`
	IsLock    bool   `json:"is_lock"`
}

type envMemoryStatus struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
}

type envFullOutput struct {
	CLI             envCLIInfo              `json:"cli"`
	Platform        string                  `json:"platform"`
	System          *gitctx.SystemInfo      `json:"system"`
	Git             *envGitInfo             `json:"git,omitempty"`
	PackageManagers []envPackageManagerInfo `json:"package_managers,omitempty"`
	Memory          *envMemoryStatus        `json:"memory,omitempty"`
}

func gatherFullEnvironment(cwd string) *envFullOutput {
	out := &envFullOutput{
		CLI: envCLIInfo{
			Version:   version,
			Commit:    commit,
			BuildDate: buildDate,
		},
		Platform: string(config.DetectPlatform()),
		System:   gitctx.CollectSystemInfo(),
	}

	// Git info
	gc := gitctx.Collect(cwd)
	if gc != nil {
		out.Git = &envGitInfo{
			Branch:        gc.CurrentBranch,
			Commit:        gc.CurrentCommit,
			RemoteURLs:    gc.RemoteURLs,
			IsDirty:       gc.IsDirty,
			IsWorktree:    gc.IsWorktree,
			CommitAuthor:  gc.HeadCommitAuthor,
			CommitEmail:   gc.HeadCommitEmail,
			CommitMessage: gc.HeadCommitMessage,
			RepoRoot:      gc.RepoRootPath,
		}
	}

	// Detect package managers (shallow scan of cwd)
	entries, err := os.ReadDir(cwd)
	if err == nil {
		seen := make(map[string]bool)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if info, ok := scan.ManifestFiles[entry.Name()]; ok {
				key := info.Ecosystem + "/" + entry.Name()
				if !seen[key] {
					seen[key] = true
					out.PackageManagers = append(out.PackageManagers, envPackageManagerInfo{
						Ecosystem: info.Ecosystem,
						Language:  info.Language,
						Manifest:  entry.Name(),
						IsLock:    info.IsLock,
					})
				}
			}
		}
	}

	// Memory status
	var memPath string
	if gc != nil && gc.RepoRootPath != "" {
		memPath = filepath.Join(gc.RepoRootPath, ".vulnetix", "memory.yaml")
	} else {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			memPath = filepath.Join(homeDir, ".vulnetix", "memory.yaml")
		}
	}
	if memPath != "" {
		_, statErr := os.Stat(memPath)
		out.Memory = &envMemoryStatus{
			Path:   memPath,
			Exists: statErr == nil,
		}
	}

	return out
}

func printEnvHumanReadable(env *envFullOutput) {
	fmt.Println("Vulnetix CLI Environment")
	fmt.Println()

	fmt.Printf("  CLI:      %s (commit: %s, built: %s)\n",
		env.CLI.Version, env.CLI.Commit, env.CLI.BuildDate)
	fmt.Printf("  Platform: %s\n", env.Platform)

	if env.System != nil {
		fmt.Printf("  System:   %s/%s", env.System.OS, env.System.Arch)
		if env.System.Hostname != "" {
			fmt.Printf(" (%s)", env.System.Hostname)
		}
		fmt.Println()
		if env.System.Shell != "" {
			fmt.Printf("  Shell:    %s\n", env.System.Shell)
		}
	}

	if env.Git != nil {
		fmt.Println()
		fmt.Println("  Git:")
		fmt.Printf("    Branch:  %s\n", env.Git.Branch)
		fmt.Printf("    Commit:  %s\n", env.Git.Commit)
		if env.Git.CommitMessage != "" {
			fmt.Printf("    Message: %s\n", env.Git.CommitMessage)
		}
		if env.Git.CommitAuthor != "" {
			fmt.Printf("    Author:  %s <%s>\n", env.Git.CommitAuthor, env.Git.CommitEmail)
		}
		for _, url := range env.Git.RemoteURLs {
			fmt.Printf("    Remote:  %s\n", url)
		}
		if env.Git.IsDirty {
			fmt.Printf("    Dirty:   yes\n")
		}
		if env.Git.IsWorktree {
			fmt.Printf("    Worktree: yes\n")
		}
		fmt.Printf("    Root:    %s\n", env.Git.RepoRoot)
	}

	if len(env.PackageManagers) > 0 {
		fmt.Println()
		fmt.Println("  Package Managers:")
		for _, pm := range env.PackageManagers {
			lockStr := ""
			if pm.IsLock {
				lockStr = " (lock)"
			}
			fmt.Printf("    %s/%s: %s%s\n", pm.Ecosystem, pm.Language, pm.Manifest, lockStr)
		}
	}

	if env.Memory != nil {
		fmt.Println()
		fmt.Println("  Memory:")
		fmt.Printf("    Path:   %s\n", env.Memory.Path)
		if env.Memory.Exists {
			fmt.Printf("    Status: exists\n")
		} else {
			fmt.Printf("    Status: not yet created\n")
		}
	}
	fmt.Println()
}
