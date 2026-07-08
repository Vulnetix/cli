package cmd

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
	pfw "github.com/vulnetix/cli/v3/pkg/packagefirewall"
)

type EcoGroups struct {
	Configured []EcoStatus
	Available  []EcoStatus
}

type EcoStatus struct {
	Ecosystem pfw.Ecosystem
	Path      string
}

func groupEcosystems(home, host string) EcoGroups {
	detected := map[string]pfw.Detected{}
	for _, d := range pfw.Detect(home, host) {
		detected[d.Ecosystem.ID] = d
	}

	var groups EcoGroups
	for _, eco := range pfw.All() {
		if d, ok := detected[eco.ID]; ok && d.Configured {
			groups.Configured = append(groups.Configured, EcoStatus{Ecosystem: eco, Path: d.Path})
			continue
		}
		groups.Available = append(groups.Available, EcoStatus{Ecosystem: eco})
	}
	return groups
}

func authSourceLabel(source string) string {
	switch {
	case source == "none":
		return "Community"
	case strings.HasPrefix(source, "environment"):
		return "Environment"
	case strings.HasPrefix(source, "keyring"):
		return "Keyring"
	case strings.HasPrefix(source, "project"):
		return "Project file"
	case strings.HasPrefix(source, "home"):
		return "Home file"
	case strings.HasPrefix(source, "netrc"):
		return "netrc"
	default:
		return source
	}
}

func tierBadge(t *display.Terminal, tier pfw.Tier) string {
	label := "[" + strings.ToUpper(string(tier)) + "]"
	switch tier {
	case pfw.TierCommunity:
		return display.Success(t, label)
	case pfw.TierPro:
		return display.Accent(t, label)
	case pfw.TierEnterprise:
		return display.Muted(t, label)
	default:
		return display.Muted(t, label)
	}
}

func planBadge(t *display.Terminal, plan string) string {
	label := strings.ToUpper(strings.TrimSpace(plan))
	if label == "" {
		label = "UNKNOWN"
	}
	switch label {
	case "COMMUNITY":
		return display.Success(t, "["+label+"]")
	case "PRO", "TEAMS":
		return display.Accent(t, "["+label+"]")
	case "ENTERPRISE":
		return display.Muted(t, "["+label+"]")
	default:
		return display.Muted(t, "["+label+"]")
	}
}

func tierRequiresPlan(tier pfw.Tier, plan string) string {
	if strings.EqualFold(plan, "unknown") || strings.TrimSpace(plan) == "" {
		return ""
	}
	if tierRank(tier) <= planRank(plan) {
		return ""
	}
	return "requires " + requiredPlan(tier)
}

func tierRank(tier pfw.Tier) int {
	switch tier {
	case pfw.TierCommunity:
		return 0
	case pfw.TierPro:
		return 1
	case pfw.TierEnterprise:
		return 3
	default:
		return 3
	}
}

func planRank(plan string) int {
	switch strings.ToUpper(strings.TrimSpace(plan)) {
	case "COMMUNITY":
		return 0
	case "PRO":
		return 1
	case "TEAMS":
		return 2
	case "ENTERPRISE":
		return 3
	default:
		return -1
	}
}

func requiredPlan(tier pfw.Tier) string {
	switch tier {
	case pfw.TierPro:
		return "Pro"
	case pfw.TierEnterprise:
		return "Enterprise"
	default:
		return "Community"
	}
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	return nil
}
