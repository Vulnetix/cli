package packagefirewall

import (
	"os"
	"path/filepath"
	"strings"
)

// Detected reports whether a package manager's config points at the firewall.
type Detected struct {
	Ecosystem  Ecosystem
	Configured bool
	Path       string // the config file that matched, when Configured
}

// ConfigPaths returns the candidate config files inspected for an ecosystem.
// (Go is detected separately via netrc + the GOPROXY environment.)
func ConfigPaths(eco Ecosystem, home string) []string {
	switch eco.ID {
	case "npm":
		return []string{filepath.Join(home, ".npmrc")}
	case "pypi":
		return []string{
			filepath.Join(home, ".config", "pip", "pip.conf"),
			filepath.Join(home, ".pip", "pip.conf"),
			filepath.Join(home, ".pypirc"),
		}
	case "cargo":
		return []string{filepath.Join(home, ".cargo", "config.toml")}
	case "gem":
		return []string{filepath.Join(home, ".gemrc")}
	case "hex":
		return []string{filepath.Join(home, ".config", "vulnetix", "package-firewall", "hex.env")}
	case "pub":
		return []string{filepath.Join(home, ".config", "vulnetix", "package-firewall", "pub.env")}
	case "maven":
		return []string{filepath.Join(home, ".m2", "settings.xml")}
	case "nuget":
		return []string{filepath.Join(home, ".nuget", "NuGet", "NuGet.Config")}
	case "composer":
		return []string{filepath.Join(home, ".composer", "config.json")}
	case "conan":
		return []string{filepath.Join(home, ".conan2", "remotes.json")}
	case "cran":
		return []string{filepath.Join(home, ".Rprofile")}
	case "helm":
		return []string{filepath.Join(home, ".config", "helm", "repositories.yaml")}
	default:
		return nil
	}
}

// Detect scans each ecosystem's config files for the firewall host and returns
// the per-ecosystem result. Ecosystems without an automatic writer are skipped.
func Detect(home, proxyHost string) []Detected {
	var out []Detected
	for _, eco := range ecosystems {
		paths := ConfigPaths(eco, home)
		if len(paths) == 0 {
			continue
		}
		d := Detected{Ecosystem: eco}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err == nil && strings.Contains(string(data), proxyHost) {
				d.Configured = true
				d.Path = p
				break
			}
		}
		out = append(out, d)
	}
	return out
}
