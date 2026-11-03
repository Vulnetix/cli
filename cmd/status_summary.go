package cmd

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/vulnetix/cli/v4/internal/display"
	pfw "github.com/vulnetix/cli/v4/pkg/packagefirewall"
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

// freeBadge marks an ecosystem as free, or as one that needs the Package Firewall add-on.
func freeBadge(t *display.Terminal, eco pfw.Ecosystem) string {
	if eco.Free {
		return display.Success(t, "[FREE]")
	}
	return display.Accent(t, "[ADD-ON]")
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

// addonRequires is the hint printed next to an ecosystem the caller has not
// unlocked. It is printed only when the console said the add-on is enforced and
// the org does NOT hold it. It is empty for a free ecosystem, for an Enterprise
// plan, for an add-on holder, with the gate off, and whenever the state is
// unknown (offline, older site, no credential): an unknown state is not a
// reason to tell someone to buy something.
func addonRequires(eco pfw.Ecosystem, plan string, st addonStatus) string {
	if eco.Free || strings.EqualFold(strings.TrimSpace(plan), "enterprise") {
		return ""
	}
	if !st.Known || !st.Enforced || st.Entitled {
		return ""
	}
	return pfw.AddonHint
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
