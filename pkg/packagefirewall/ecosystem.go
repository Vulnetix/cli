package packagefirewall

import (
	"fmt"
	"strings"
)

// AddonName is the paid add-on that unlocks every registry that is not free.
const AddonName = "Package Firewall add-on"

// AddonHint is the one-line reason shown next to an ecosystem the caller has not unlocked.
const AddonHint = "requires the " + AddonName

type Ecosystem struct {
	ID          string
	Command     string
	DisplayName string
	Prefix      string
	// Free is true for the registries every org may use without the add-on. The
	// firewall serves go-dev and aur free; every other registry, including the Go
	// proxy, needs the Package Firewall add-on.
	Free       bool
	LiveWriter bool
}

var ecosystems = []Ecosystem{
	{ID: "go", Command: "go", DisplayName: "Go", Prefix: "", LiveWriter: false},
	{ID: "npm", Command: "npm", DisplayName: "npm", Prefix: "npm", LiveWriter: true},
	{ID: "pypi", Command: "pypi", DisplayName: "PyPI", Prefix: "pypi", LiveWriter: true},
	{ID: "cargo", Command: "cargo", DisplayName: "Cargo", Prefix: "cargo", LiveWriter: true},
	{ID: "gem", Command: "gem", DisplayName: "RubyGems", Prefix: "gem", LiveWriter: true},
	{ID: "hex", Command: "hex", DisplayName: "Hex", Prefix: "hex", LiveWriter: true},
	{ID: "pub", Command: "pub", DisplayName: "pub.dev", Prefix: "pub", LiveWriter: true},
	{ID: "maven", Command: "maven", DisplayName: "Maven", Prefix: "maven", LiveWriter: true},
	{ID: "nuget", Command: "nuget", DisplayName: "NuGet", Prefix: "nuget", LiveWriter: true},
	{ID: "composer", Command: "composer", DisplayName: "Composer", Prefix: "composer", LiveWriter: true},
	{ID: "conan", Command: "conan", DisplayName: "Conan", Prefix: "conan", LiveWriter: true},
	{ID: "conda", Command: "conda", DisplayName: "Conda", Prefix: "conda", LiveWriter: false},
	{ID: "cran", Command: "cran", DisplayName: "CRAN", Prefix: "cran", LiveWriter: true},
	{ID: "julia", Command: "julia", DisplayName: "Julia", Prefix: "julia", LiveWriter: false},
	{ID: "oci", Command: "docker", DisplayName: "Docker / OCI", Prefix: "v2", LiveWriter: false},
	{ID: "debian", Command: "debian", DisplayName: "Debian / Ubuntu", Prefix: "debian", LiveWriter: false},
	{ID: "rpm", Command: "rpm", DisplayName: "RPM", Prefix: "rpm", LiveWriter: false},
	{ID: "alpine", Command: "alpine", DisplayName: "Alpine", Prefix: "alpine", LiveWriter: false},
	{ID: "helm", Command: "helm", DisplayName: "Helm", Prefix: "helm", LiveWriter: true},
	{ID: "chef", Command: "chef", DisplayName: "Chef", Prefix: "chef", LiveWriter: false},
	{ID: "terraform", Command: "terraform", DisplayName: "Terraform", Prefix: "terraform", LiveWriter: false},
	// Arch Linux: one command configures paru/yay (AUR, /aur prefix) and stages a
	// pacman mirrorlist for the official repos (/arch prefix). AUR is free; the pacman
	// mirrorlist (/arch) needs the Package Firewall add-on.
	{ID: "aur", Command: "aur", DisplayName: "Arch Linux", Prefix: "aur", Free: true, LiveWriter: true},
	{ID: "homebrew", Command: "homebrew", DisplayName: "Homebrew", Prefix: "homebrew", LiveWriter: true},
}

func All() []Ecosystem {
	out := make([]Ecosystem, len(ecosystems))
	copy(out, ecosystems)
	return out
}

func ByCommand(command string) (Ecosystem, bool) {
	for _, eco := range ecosystems {
		if eco.Command == command {
			return eco, true
		}
	}
	return Ecosystem{}, false
}

func ProxyURL(base string, eco Ecosystem) string {
	u := strings.TrimRight(strings.TrimSpace(base), "/")
	if u == "" {
		u = "https://packages.vulnetix.com"
	}
	if eco.Prefix == "" {
		return u
	}
	return u + "/" + eco.Prefix
}

func ProxyURLWithSlash(base string, eco Ecosystem) string {
	return strings.TrimRight(ProxyURL(base, eco), "/") + "/"
}

func RequireWriter(eco Ecosystem) error {
	if eco.LiveWriter {
		return nil
	}
	return fmt.Errorf("automatic %s configuration is not implemented yet", eco.DisplayName)
}

// freeIDs are the firewall ecosystem ids that need no add-on. go-dev is the
// pkg.go.dev API proxy; it has its own command and is not in All().
var freeIDs = map[string]bool{"go-dev": true, "aur": true}

// IsFree reports whether the ecosystem id (the firewall's, such as "aur" or
// "go-dev") needs no add-on.
func IsFree(id string) bool { return freeIDs[strings.ToLower(strings.TrimSpace(id))] }

// AddonNote is extra guidance for a setup that configures more than one firewall
// prefix with different entitlements. The aur command also stages the pacman
// mirrorlist for the official Arch repositories (the /arch prefix), and that part
// needs the add-on while AUR does not.
func AddonNote(eco Ecosystem) string {
	if eco.ID == "aur" {
		return "AUR is free. The pacman mirrorlist for the official Arch repositories (/arch) " + AddonHint + "."
	}
	return ""
}
