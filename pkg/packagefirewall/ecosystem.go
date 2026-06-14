package packagefirewall

import (
	"fmt"
	"strings"
)

type Tier string

const (
	TierCommunity  Tier = "community"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
)

type Ecosystem struct {
	ID          string
	Command     string
	DisplayName string
	Prefix      string
	Tier        Tier
	LiveWriter  bool
}

var ecosystems = []Ecosystem{
	{ID: "go", Command: "go", DisplayName: "Go", Prefix: "", Tier: TierCommunity, LiveWriter: false},
	{ID: "npm", Command: "npm", DisplayName: "npm", Prefix: "npm", Tier: TierPro, LiveWriter: true},
	{ID: "pypi", Command: "pypi", DisplayName: "PyPI", Prefix: "pypi", Tier: TierPro, LiveWriter: true},
	{ID: "cargo", Command: "cargo", DisplayName: "Cargo", Prefix: "cargo", Tier: TierPro, LiveWriter: true},
	{ID: "gem", Command: "gem", DisplayName: "RubyGems", Prefix: "gem", Tier: TierPro, LiveWriter: true},
	{ID: "hex", Command: "hex", DisplayName: "Hex", Prefix: "hex", Tier: TierPro, LiveWriter: true},
	{ID: "pub", Command: "pub", DisplayName: "pub.dev", Prefix: "pub", Tier: TierPro, LiveWriter: true},
	{ID: "maven", Command: "maven", DisplayName: "Maven", Prefix: "maven", Tier: TierPro, LiveWriter: true},
	{ID: "nuget", Command: "nuget", DisplayName: "NuGet", Prefix: "nuget", Tier: TierPro, LiveWriter: true},
	{ID: "composer", Command: "composer", DisplayName: "Composer", Prefix: "composer", Tier: TierPro, LiveWriter: true},
	{ID: "conan", Command: "conan", DisplayName: "Conan", Prefix: "conan", Tier: TierPro, LiveWriter: true},
	{ID: "conda", Command: "conda", DisplayName: "Conda", Prefix: "conda", Tier: TierPro, LiveWriter: false},
	{ID: "cran", Command: "cran", DisplayName: "CRAN", Prefix: "cran", Tier: TierPro, LiveWriter: true},
	{ID: "julia", Command: "julia", DisplayName: "Julia", Prefix: "julia", Tier: TierPro, LiveWriter: false},
	{ID: "oci", Command: "docker", DisplayName: "Docker / OCI", Prefix: "v2", Tier: TierEnterprise, LiveWriter: false},
	{ID: "debian", Command: "debian", DisplayName: "Debian / Ubuntu", Prefix: "debian", Tier: TierEnterprise, LiveWriter: false},
	{ID: "rpm", Command: "rpm", DisplayName: "RPM", Prefix: "rpm", Tier: TierEnterprise, LiveWriter: false},
	{ID: "alpine", Command: "alpine", DisplayName: "Alpine", Prefix: "alpine", Tier: TierEnterprise, LiveWriter: false},
	{ID: "helm", Command: "helm", DisplayName: "Helm", Prefix: "helm", Tier: TierEnterprise, LiveWriter: true},
	{ID: "chef", Command: "chef", DisplayName: "Chef", Prefix: "chef", Tier: TierEnterprise, LiveWriter: false},
	{ID: "terraform", Command: "terraform", DisplayName: "Terraform", Prefix: "terraform", Tier: TierEnterprise, LiveWriter: false},
	// Arch Linux: one command configures paru/yay (AUR, /aur prefix) and stages a
	// pacman mirrorlist for the official repos (/arch prefix). Free (community).
	{ID: "aur", Command: "aur", DisplayName: "Arch Linux", Prefix: "aur", Tier: TierCommunity, LiveWriter: true},
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
