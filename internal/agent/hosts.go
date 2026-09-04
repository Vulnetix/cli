package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Surface is one way a host can be wired to Vulnetix.
type Surface string

const (
	// SurfaceSkills means the host reads Agent Skills from a directory.
	SurfaceSkills Surface = "skills"
	// SurfaceHooks means the host runs lifecycle hooks, so the dependency
	// guard can answer at the moment of a tool call.
	SurfaceHooks Surface = "hooks"
	// SurfaceMCP means the host speaks the Model Context Protocol and can be
	// pointed at mcp.vulnetix.com.
	SurfaceMCP Surface = "mcp"
)

// HookDialect is how a host spells its hook configuration.
type HookDialect string

const (
	// DialectNone means this build cannot configure the host's hooks.
	//
	// It is not the same as the host having none. Several hosts document a hook
	// system that has not been verified against this CLI, and claiming support
	// that has not been tested is how the previous install docs came to promise
	// a directory Codex does not read.
	DialectNone HookDialect = ""
	// DialectClaudeCode is settings.json with a hooks object keyed by event.
	DialectClaudeCode HookDialect = "claude-code"
	// DialectCodex is hooks.json with a description and a hooks object.
	DialectCodex HookDialect = "codex"
)

// Host is one coding agent this CLI can wire up.
//
// The table is the single source of truth for what is supported. The installer
// acts on it, `agent hosts` prints it, and the documentation and marketing
// matrices are generated from that output — so a page cannot claim a capability
// the installer does not implement.
type Host struct {
	// ID is the stable identifier, matching what `gh skill install --agent`
	// calls the host wherever one exists.
	ID string
	// Name is what the host calls itself.
	Name string

	// SkillDirs are the user-scope skill directories, most preferred first.
	// Several hosts read the interoperable ~/.agents/skills alongside their own.
	SkillDirs []string
	// ProjectSkillDirs are the repository-scope equivalents.
	ProjectSkillDirs []string

	// HookDialect is how this host's hooks are configured, if this build can.
	HookDialect HookDialect
	// HookConfig is the user-scope file the hook configuration lives in.
	HookConfig string

	// MCP records whether the host can be pointed at an MCP server.
	MCP bool

	// Detect are paths whose existence means the host is installed. A missing
	// binary is not proof of absence — several hosts ship as an extension
	// rather than a command — so a configuration directory counts.
	Detect []string
}

// Supports reports whether this build can wire a surface for this host.
func (h Host) Supports(s Surface) bool {
	switch s {
	case SurfaceSkills:
		return len(h.SkillDirs) > 0
	case SurfaceHooks:
		return h.HookDialect != DialectNone
	case SurfaceMCP:
		return h.MCP
	}
	return false
}

// Surfaces lists what this build can wire for the host, in a stable order.
func (h Host) Surfaces() []Surface {
	var out []Surface
	for _, s := range []Surface{SurfaceSkills, SurfaceHooks, SurfaceMCP} {
		if h.Supports(s) {
			out = append(out, s)
		}
	}
	return out
}

// Hosts is every agent this CLI knows how to wire.
//
// Two rules govern entries here. A skills directory is only listed when it is
// the path the host actually reads, verified against that host's own
// documentation rather than inferred from its name. A hook dialect is only
// named when this CLI has been run against that host and its response accepted;
// everything else is skills-only, which is honest and still useful.
var Hosts = []Host{
	{
		ID:               "claude-code",
		Name:             "Claude Code",
		SkillDirs:        []string{"~/.claude/skills"},
		ProjectSkillDirs: []string{".claude/skills"},
		HookDialect:      DialectClaudeCode,
		HookConfig:       "~/.claude/settings.json",
		MCP:              true,
		Detect:           []string{"~/.claude"},
	},
	{
		ID:   "codex",
		Name: "OpenAI Codex",
		// Codex reads the interoperable path, not ~/.codex/skills. The previous
		// install documentation had this wrong for every Codex user.
		SkillDirs:        []string{"~/.agents/skills"},
		ProjectSkillDirs: []string{".agents/skills"},
		HookDialect:      DialectCodex,
		HookConfig:       "~/.codex/hooks.json",
		MCP:              true,
		Detect:           []string{"~/.codex"},
	},
	{
		ID:               "cursor",
		Name:             "Cursor",
		SkillDirs:        []string{"~/.agents/skills", "~/.cursor/skills"},
		ProjectSkillDirs: []string{".agents/skills", ".cursor/skills"},
		MCP:              true,
		Detect:           []string{"~/.cursor"},
	},
	{
		ID:               "gemini-cli",
		Name:             "Gemini CLI",
		SkillDirs:        []string{"~/.agents/skills", "~/.gemini/skills"},
		ProjectSkillDirs: []string{".agents/skills", ".gemini/skills"},
		MCP:              true,
		Detect:           []string{"~/.gemini"},
	},
	{
		ID:               "github-copilot",
		Name:             "GitHub Copilot",
		SkillDirs:        []string{"~/.copilot/skills"},
		ProjectSkillDirs: []string{".github/skills"},
		MCP:              true,
		Detect:           []string{"~/.copilot"},
	},
	{
		ID:               "opencode",
		Name:             "opencode",
		SkillDirs:        []string{"~/.config/opencode/skills"},
		ProjectSkillDirs: []string{".opencode/skills"},
		MCP:              true,
		Detect:           []string{"~/.config/opencode"},
	},
	{
		ID:               "pi",
		Name:             "Pi",
		SkillDirs:        []string{"~/.agents/skills", "~/.pi/agent/skills"},
		ProjectSkillDirs: []string{".agents/skills", ".pi/skills"},
		MCP:              true,
		Detect:           []string{"~/.pi"},
	},
	{
		ID:               "windsurf",
		Name:             "Windsurf",
		SkillDirs:        []string{"~/.codeium/windsurf/skills"},
		ProjectSkillDirs: []string{".windsurf/skills"},
		MCP:              true,
		Detect:           []string{"~/.codeium/windsurf"},
	},
	{
		ID:               "zed",
		Name:             "Zed",
		SkillDirs:        []string{"~/.agents/skills"},
		ProjectSkillDirs: []string{".agents/skills"},
		MCP:              true,
		Detect:           []string{"~/.config/zed"},
	},
	{
		ID:               "amp",
		Name:             "Amp",
		SkillDirs:        []string{"~/.config/agents/skills"},
		ProjectSkillDirs: []string{".agents/skills"},
		MCP:              true,
		Detect:           []string{"~/.config/amp"},
	},
}

// HostByID finds a host by its identifier.
func HostByID(id string) (Host, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, h := range Hosts {
		if h.ID == id {
			return h, true
		}
	}
	return Host{}, false
}

// Installed reports whether the host appears to be present on this machine.
func (h Host) Installed() bool {
	for _, p := range h.Detect {
		if _, err := os.Stat(ExpandHome(p)); err == nil {
			return true
		}
	}
	return false
}

// DetectHosts lists the hosts present on this machine.
func DetectHosts() []Host {
	var out []Host
	for _, h := range Hosts {
		if h.Installed() {
			out = append(out, h)
		}
	}
	return out
}

// ExpandHome resolves a leading ~ against the user's home directory.
func ExpandHome(p string) string {
	if !strings.HasPrefix(p, "~") {
		return filepath.FromSlash(p)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.FromSlash(p)
	}
	return filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(p, "~/")))
}

// HookCommand is the command a host runs for every hook event.
//
// The binary's absolute path rather than a bare name: a host does not
// necessarily inherit the shell PATH that installed the CLI, and a hook that
// cannot be found fails silently on some hosts.
func HookCommand() string {
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		return "vulnetix agent hook"
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if runtime.GOOS == "windows" || !strings.ContainsAny(exe, " \t") {
		return exe + " agent hook"
	}
	return `"` + exe + `" agent hook`
}
