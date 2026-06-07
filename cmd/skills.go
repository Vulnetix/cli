package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
)

var (
	skillsAgent string
	skillsSkill string
)

var knownVulnetixSkills = []string{
	"attack-mapping", "capabilities-detect", "code-review-security",
	"compliance-report", "container-scan", "dashboard", "dep-add-guard",
	"dep-resolve", "detection-rules", "eol-check", "exploit-test",
	"exploits", "exploits-search", "find-skills", "fix", "iac-scan",
	"incident-respond", "ioc-pivot", "kev-watch", "license-check",
	"package-search", "remediation", "safe-version", "sast-scan",
	"sbom-generate", "secret-scan", "secure-code-write", "soc-triage",
	"threat-feed", "typosquat-check", "verify-fix", "vex-publish", "vuln",
}

var skillsCmd = &cobra.Command{
	Use:   "skills",
	Short: "Manage Vulnetix agent skills",
	Long:  `Manage the installation, checking, updating, and removal of Vulnetix skills for various AI coding assistants.`,
}

var skillsInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Vulnetix skills for supported agents",
	Long: `Install Vulnetix skills into your AI coding assistant.

By default, it auto-detects available tools and installs best effort:
  1. If 'npx' is available, runs: npx skills add --all -y Vulnetix/pix-ai-coding-assistant
  2. If 'claude' is available (and no npx), runs: claude plugin marketplace add Vulnetix/pix-ai-coding-assistant AND claude plugin install vulnetix@vulnetix-plugins
  3. If 'gh' is available (and no npx), detects installed agents and runs: gh skills add Vulnetix/claude-code-plugin <skill> --agent <agent> -f --scope user
     for each installed agent and supported skill.

Supported agents for 'gh skills add':
  github-copilot, claude-code, cursor, codex, gemini-cli, antigravity, adal, amp, augment, bob, cline, codebuddy, command-code, continue, cortex, crush, deepagents, droid, firebender, goose, iflow-cli, junie, kilo, kimi-cli, kiro-cli, kode, mcpjam, mistral-vibe, mux, neovate, openclaw, opencode, openhands, pi, pochi, qoder, qwen-code, replit, roo, trae, trae-cn, universal, warp, windsurf, zencoder

Supported agents for 'npx skills add':
  aider-desk, amp, replit, universal, antigravity, antigravity-cli, astrbot, autohand-code, augment, bob, claude-code, openclaw, cline, dexto, kimi-code-cli, loaf, warp, zed, codearts-agent, codebuddy, codemaker, codestudio, codex, command-code, continue, cortex, crush, cursor, deepagents, devin, droid, firebender, forgecode, gemini-cli, github-copilot, goose, hermes-agent, inference-sh, jazz, junie, iflow-cli, kilo, kiro-cli, kode, lingma, mcpjam, mistral-vibe, moxby, mux, opencode, openhands, ona, pi, qoder, qoder-cn, qwen-code, reasonix, rovodev, roo, tabnine-cli, terramind, tinycloud, trae, trae-cn, windsurf, zencoder, zenflow, neovate, pochi, promptscript, adal

You can explicitly target an agent and/or skill using --agent and --skill flags.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dc := display.FromCommand(cmd)
		t := dc.Term

		fmt.Println(display.Subheader(t, "Installing Vulnetix Skills"))

		if skillsSkill != "" || skillsAgent != "" {
			return runExplicitInstall(cmd)
		}

		if commandExists("npx") {
			fmt.Printf("  %s Detected %s, installing best effort...\n", display.CheckMark(t), display.Bold(t, "npx"))
			if err := runCommand("npx", "skills", "add", "--all", "-y", "Vulnetix/pix-ai-coding-assistant"); err != nil {
				fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, fmt.Sprintf("npx skills add failed: %v", err)))
			} else {
				fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Successfully installed via npx"))
			}
			return nil
		}

		if commandExists("claude") {
			fmt.Printf("  %s Detected %s, installing best effort...\n", display.CheckMark(t), display.Bold(t, "claude"))
			if err := runCommand("claude", "plugin", "marketplace", "add", "Vulnetix/pix-ai-coding-assistant"); err != nil {
				fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, fmt.Sprintf("claude plugin marketplace add failed: %v", err)))
			} else {
				fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Added to claude plugin marketplace"))
			}
			if err := runCommand("claude", "plugin", "install", "vulnetix@vulnetix-plugins"); err != nil {
				fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, fmt.Sprintf("claude plugin install failed: %v", err)))
			} else {
				fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Successfully installed vulnetix@vulnetix-plugins"))
			}
			return nil
		}

		if commandExists("gh") {
			fmt.Printf("  %s Detected %s, detecting installed agents...\n", display.CheckMark(t), display.Bold(t, "gh"))
			installedAgents := detectInstalledAgents()
			if len(installedAgents) == 0 {
				fmt.Printf("    %s %s\n", display.WarningMark(t), display.Muted(t, "No supported agents detected with existing skill directories. Skipping 'gh skills add'."))
				fmt.Printf("    %s %s\n", display.Muted(t, "ℹ"), "Tip: You can explicitly target an agent using --agent and --skill flags.")
			} else {
				skills := []string{
					"attack-mapping", "capabilities-detect", "code-review-security",
					"compliance-report", "container-scan", "dashboard", "dep-add-guard",
					"dep-resolve", "detection-rules", "eol-check", "exploit-test",
					"exploits", "exploits-search", "fix", "iac-scan", "incident-respond",
					"ioc-pivot", "kev-watch", "license-check",
				}
				for _, agent := range installedAgents {
					fmt.Printf("    %s Installing skills for %s...\n", display.Muted(t, "•"), display.Bold(t, agent))
					for _, skill := range skills {
						if err := runCommand("gh", "skills", "add", "Vulnetix/claude-code-plugin", skill, "--agent", agent, "-f", "--scope", "user"); err != nil {
							fmt.Printf("      %s %s\n", display.CrossMark(t), display.ErrorStyle(t, fmt.Sprintf("%s: %v", skill, err)))
						} else {
							fmt.Printf("      %s %s\n", display.CheckMark(t), display.Success(t, skill))
						}
					}
				}
			}
			return nil
		}

		fmt.Printf("  %s %s\n", display.CrossMark(t), display.ErrorStyle(t, "No installation methods (npx, claude, gh) were detected."))
		fmt.Println(display.Muted(t, "Please ensure you have 'npx', 'claude', or 'gh' installed, or use --agent and --skill flags to target a specific installation."))
		return nil
	},
}

var skillsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check installed Vulnetix skills",
	Long:  `Check which Vulnetix skills are currently installed for supported agents.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dc := display.FromCommand(cmd)
		t := dc.Term

		fmt.Println(display.Subheader(t, "Checking Installed Vulnetix Skills"))

		installedAgents := detectInstalledAgents()
		if len(installedAgents) == 0 {
			fmt.Println(display.Muted(t, "No supported agents detected with existing skill directories."))
			return nil
		}

		knownSkillsSet := make(map[string]bool)
		for _, skill := range knownVulnetixSkills {
			knownSkillsSet[skill] = true
		}

		foundAny := false
		for _, agent := range installedAgents {
			dirs := getAgentSkillDirs(agent)
			for _, dir := range dirs {
				expandedDir := os.ExpandEnv(dir)
				if strings.HasPrefix(expandedDir, "~") {
					home, _ := os.UserHomeDir()
					expandedDir = filepath.Join(home, expandedDir[1:])
				}
				if _, err := os.Stat(expandedDir); err == nil {
					entries, _ := os.ReadDir(expandedDir)
					var vulnetixSkills []string
					for _, entry := range entries {
						if knownSkillsSet[entry.Name()] {
							skillPath := filepath.Join(expandedDir, entry.Name())
							if info, err := os.Stat(skillPath); err == nil && info.IsDir() {
								vulnetixSkills = append(vulnetixSkills, entry.Name())
							}
						}
					}
					if len(vulnetixSkills) > 0 {
						foundAny = true
						var formattedSkills []string
						for _, s := range vulnetixSkills {
							formattedSkills = append(formattedSkills, display.Success(t, s))
						}
						fmt.Printf("  %s Agent %s (%s)\n", display.CheckMark(t), display.Bold(t, agent), display.Muted(t, expandedDir))
						fmt.Printf("    └─ Skills: %s\n", strings.Join(formattedSkills, display.Muted(t, ", ")))
					}
				}
			}
		}

		if !foundAny {
			fmt.Println(display.Muted(t, "No Vulnetix skills detected in any supported agent directories."))
		}

		return nil
	},
}

var skillsUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall Vulnetix skills",
	Long:  `Uninstall Vulnetix skills from supported agents.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dc := display.FromCommand(cmd)
		t := dc.Term

		fmt.Println(display.Subheader(t, "Uninstalling Vulnetix Skills"))

		if commandExists("npx") {
			fmt.Printf("  %s Running %s...\n", display.Muted(t, "•"), display.Bold(t, "npx skills remove --all"))
			if err := runCommand("npx", "skills", "remove", "--all"); err != nil {
				fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
			} else {
				fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Uninstalled successfully"))
			}
		} else {
			fmt.Printf("  %s %s not found.\n", display.WarningMark(t), display.Bold(t, "npx"))
			fmt.Println(display.Muted(t, "Please manually remove skills from your agent's skill directory:"))
			installedAgents := detectInstalledAgents()
			for _, agent := range installedAgents {
				dirs := getAgentSkillDirs(agent)
				for _, dir := range dirs {
					expandedDir := os.ExpandEnv(dir)
					if strings.HasPrefix(expandedDir, "~") {
						home, _ := os.UserHomeDir()
						expandedDir = filepath.Join(home, expandedDir[1:])
					}
					fmt.Printf("    %s %s\n", display.Muted(t, "→"), display.Bold(t, expandedDir))
				}
			}
		}
		return nil
	},
}

var skillsUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update installed Vulnetix skills",
	Long:  `Update installed Vulnetix skills for supported agents.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dc := display.FromCommand(cmd)
		t := dc.Term

		fmt.Println(display.Subheader(t, "Updating Vulnetix Skills"))

		if commandExists("npx") {
			fmt.Printf("  %s Running %s...\n", display.Muted(t, "•"), display.Bold(t, "npx skills update"))
			if err := runCommand("npx", "skills", "update", "-y"); err != nil {
				fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
			} else {
				fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Updated successfully"))
			}
		} else if commandExists("gh") {
			fmt.Printf("  %s Running %s...\n", display.Muted(t, "•"), display.Bold(t, "gh skills update"))
			if err := runCommand("gh", "skills", "update", "--all"); err != nil {
				fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
			} else {
				fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Updated successfully"))
			}
		} else if commandExists("claude") {
			fmt.Printf("  %s Running %s...\n", display.Muted(t, "•"), display.Bold(t, "claude plugin marketplace update"))
			if err := runCommand("claude", "plugin", "marketplace", "update"); err != nil {
				fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
			} else {
				fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Updated successfully"))
			}
		} else {
			fmt.Printf("  %s %s\n", display.CrossMark(t), display.ErrorStyle(t, "No supported tool (npx, gh, claude) found for updating skills."))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(skillsCmd)

	skillsInstallCmd.Flags().StringVar(&skillsAgent, "agent", "", "Target a specific agent (e.g., claude-code, codex, pi)")
	skillsInstallCmd.Flags().StringVar(&skillsSkill, "skill", "", "Target a specific skill (e.g., fix, exploits)")
	skillsCmd.AddCommand(skillsInstallCmd)
	skillsCmd.AddCommand(skillsCheckCmd)
	skillsCmd.AddCommand(skillsUninstallCmd)
	skillsCmd.AddCommand(skillsUpdateCmd)
}

func runExplicitInstall(cmd *cobra.Command) error {
	dc := display.FromCommand(cmd)
	t := dc.Term

	var tools []string
	if commandExists("npx") {
		tools = append(tools, "npx")
	}
	if commandExists("gh") {
		tools = append(tools, "gh")
	}
	if commandExists("claude") {
		tools = append(tools, "claude")
	}

	if len(tools) == 0 {
		return fmt.Errorf("%s: no supported tools (npx, gh, claude) found in PATH", display.ErrorStyle(t, "Error"))
	}

	skillsToInstall := []string{skillsSkill}
	if skillsSkill == "" {
		skillsToInstall = []string{
			"attack-mapping", "capabilities-detect", "code-review-security",
			"compliance-report", "container-scan", "dashboard", "dep-add-guard",
			"dep-resolve", "detection-rules", "eol-check", "exploit-test",
			"exploits", "exploits-search", "fix", "iac-scan", "incident-respond",
			"ioc-pivot", "kev-watch", "license-check",
		}
	}

	agentsToInstall := []string{skillsAgent}
	if skillsAgent == "" {
		agentsToInstall = detectInstalledAgents()
		if len(agentsToInstall) == 0 {
			fmt.Println(display.Muted(t, "No installed agents detected. Please specify --agent or install an agent first."))
			return nil
		}
	}

	for _, tool := range tools {
		fmt.Printf("\n%s Installing via %s...\n", display.Subheader(t, "Action"), display.Bold(t, tool))
		if tool == "npx" {
			for _, agent := range agentsToInstall {
				fmt.Printf("  %s Installing skills for agent %s...\n", display.Muted(t, "•"), display.Bold(t, agent))
				if err := runCommand("npx", "skills", "add", "Vulnetix/pix-ai-coding-assistant", "--agent", agent); err != nil {
					fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
				} else {
					fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Installed successfully"))
				}
			}
		} else if tool == "gh" {
			for _, skill := range skillsToInstall {
				for _, agent := range agentsToInstall {
					fmt.Printf("  %s Installing %s for %s...\n", display.Muted(t, "•"), display.Bold(t, skill), display.Bold(t, agent))
					if err := runCommand("gh", "skills", "add", "Vulnetix/claude-code-plugin", skill, "--agent", agent, "-f", "--scope", "user"); err != nil {
						fmt.Printf("    %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
					} else {
						fmt.Printf("    %s %s\n", display.CheckMark(t), display.Success(t, "Installed successfully"))
					}
				}
			}
		} else if tool == "claude" {
			if err := runCommand("claude", "plugin", "marketplace", "add", "Vulnetix/pix-ai-coding-assistant"); err != nil {
				fmt.Printf("  %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
			} else {
				fmt.Printf("  %s %s\n", display.CheckMark(t), display.Success(t, "Added to marketplace"))
			}
			if err := runCommand("claude", "plugin", "install", "vulnetix@vulnetix-plugins"); err != nil {
				fmt.Printf("  %s %s\n", display.CrossMark(t), display.ErrorStyle(t, err.Error()))
			} else {
				fmt.Printf("  %s %s\n", display.CheckMark(t), display.Success(t, "Installed successfully"))
			}
		}
	}
	return nil
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func runCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("%s: %v, stderr: %s", strings.Join(append([]string{name}, arg...), " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func detectInstalledAgents() []string {
	var installed []string
	for agent, dirs := range agentDirs {
		found := false
		for _, dir := range dirs {
			expanded := os.ExpandEnv(dir)
			if strings.HasPrefix(expanded, "~") {
				home, _ := os.UserHomeDir()
				expanded = filepath.Join(home, expanded[1:])
			}
			if _, err := os.Stat(expanded); err == nil {
				found = true
				break
			}
		}
		if found {
			installed = append(installed, agent)
		} else if commandExists(agent) {
			installed = append(installed, agent)
		}
	}
	return installed
}

func getAgentSkillDirs(agent string) []string {
	if dirs, ok := agentDirs[agent]; ok {
		return dirs
	}
	return []string{"~/.agents/skills", "~/.config/agents/skills"}
}

var agentDirs = map[string][]string{
	"aider-desk":     {"~/.aider-desk/skills"},
	"amp":            {"~/.config/agents/skills"},
	"replit":         {"~/.config/agents/skills"},
	"universal":      {"~/.config/agents/skills"},
	"antigravity":    {"~/.gemini/antigravity/skills"},
	"antigravity-cli":{"~/.gemini/antigravity-cli/skills"},
	"astrbot":        {"~/.astrbot/data/skills"},
	"autohand-code":  {"~/.autohand/skills"},
	"augment":        {"~/.augment/skills"},
	"bob":            {"~/.bob/skills"},
	"claude-code":    {"~/.claude/skills"},
	"openclaw":       {"~/.openclaw/skills"},
	"cline":          {"~/.agents/skills"},
	"dexto":          {"~/.agents/skills"},
	"kimi-code-cli":  {"~/.agents/skills"},
	"loaf":           {"~/.agents/skills"},
	"warp":           {"~/.agents/skills"},
	"zed":            {"~/.agents/skills"},
	"codearts-agent": {"~/.codeartsdoer/skills"},
	"codebuddy":      {"~/.codebuddy/skills"},
	"codemaker":      {"~/.codemaker/skills"},
	"codestudio":     {"~/.codestudio/skills"},
	"codex":          {"~/.codex/skills"},
	"command-code":   {"~/.commandcode/skills"},
	"continue":       {"~/.continue/skills"},
	"cortex":         {"~/.snowflake/cortex/skills"},
	"crush":          {"~/.config/crush/skills"},
	"cursor":         {"~/.cursor/skills"},
	"deepagents":     {"~/.deepagents/agent/skills"},
	"devin":          {"~/.config/devin/skills"},
	"droid":          {"~/.factory/skills"},
	"firebender":     {"~/.firebender/skills"},
	"forgecode":      {"~/.forge/skills"},
	"gemini-cli":     {"~/.gemini/skills"},
	"github-copilot": {"~/.copilot/skills"},
	"goose":          {"~/.config/goose/skills"},
	"hermes-agent":   {"~/.hermes/skills"},
	"inference-sh":   {"~/.inferencesh/skills"},
	"jazz":           {"~/.jazz/skills"},
	"junie":          {"~/.junie/skills"},
	"iflow-cli":      {"~/.iflow/skills"},
	"kilo":           {"~/.kilocode/skills"},
	"kiro-cli":       {"~/.kiro/skills"},
	"kode":           {"~/.kode/skills"},
	"lingma":         {"~/.lingma/skills"},
	"mcpjam":         {"~/.mcpjam/skills"},
	"mistral-vibe":   {"~/.vibe/skills"},
	"moxby":          {"~/.moxby/skills"},
	"mux":            {"~/.mux/skills"},
	"opencode":       {"~/.config/opencode/skills"},
	"openhands":      {"~/.openhands/skills"},
	"ona":            {"~/.ona/skills"},
	"pi":             {"~/.pi/agent/skills"},
	"qoder":          {"~/.qoder/skills"},
	"qoder-cn":       {"~/.qoder-cn/skills"},
	"qwen-code":      {"~/.qwen/skills"},
	"reasonix":       {"~/.reasonix/skills"},
	"rovodev":        {"~/.rovodev/skills"},
	"roo":            {"~/.roo/skills"},
	"tabnine-cli":    {"~/.tabnine/agent/skills"},
	"terramind":      {"~/.terramind/skills"},
	"tinycloud":      {"~/.tinycloud/skills"},
	"trae":           {"~/.trae/skills"},
	"trae-cn":        {"~/.trae-cn/skills"},
	"windsurf":       {"~/.codeium/windsurf/skills"},
	"zencoder":       {"~/.zencoder/skills"},
	"zenflow":        {"~/.zencoder/skills"},
	"neovate":        {"~/.neovate/skills"},
	"pochi":          {"~/.pochi/skills"},
	"promptscript":   {".agents/skills"},
	"adal":           {"~/.adal/skills"},
}
