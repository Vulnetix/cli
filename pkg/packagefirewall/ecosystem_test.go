package packagefirewall

import "testing"

func TestAllMatchesPlan(t *testing.T) {
	got := All()
	if len(got) != 23 {
		t.Fatalf("All() length = %d, want 23", len(got))
	}
	cases := map[string]struct {
		prefix string
		tier   Tier
	}{
		"go":        {"", TierCommunity},
		"npm":       {"npm", TierPro},
		"pypi":      {"pypi", TierPro},
		"cargo":     {"cargo", TierPro},
		"gem":       {"gem", TierPro},
		"hex":       {"hex", TierPro},
		"pub":       {"pub", TierPro},
		"maven":     {"maven", TierPro},
		"nuget":     {"nuget", TierPro},
		"composer":  {"composer", TierPro},
		"conan":     {"conan", TierPro},
		"conda":     {"conda", TierPro},
		"cran":      {"cran", TierPro},
		"julia":     {"julia", TierPro},
		"docker":    {"v2", TierEnterprise},
		"debian":    {"debian", TierEnterprise},
		"rpm":       {"rpm", TierEnterprise},
		"alpine":    {"alpine", TierEnterprise},
		"helm":      {"helm", TierEnterprise},
		"chef":      {"chef", TierEnterprise},
		"terraform": {"terraform", TierEnterprise},
		"homebrew":  {"homebrew", TierPro},
	}
	for command, want := range cases {
		eco, ok := ByCommand(command)
		if !ok {
			t.Fatalf("ByCommand(%q) missing", command)
		}
		if eco.Prefix != want.prefix || eco.Tier != want.tier {
			t.Errorf("ByCommand(%q) = prefix %q tier %q, want prefix %q tier %q", command, eco.Prefix, eco.Tier, want.prefix, want.tier)
		}
	}
}

func TestProxyURL(t *testing.T) {
	npm, _ := ByCommand("npm")
	if got := ProxyURL("https://packages.vulnetix.com/", npm); got != "https://packages.vulnetix.com/npm" {
		t.Errorf("ProxyURL npm = %q", got)
	}
	goEco, _ := ByCommand("go")
	if got := ProxyURL("https://packages.vulnetix.com/", goEco); got != "https://packages.vulnetix.com" {
		t.Errorf("ProxyURL go = %q", got)
	}
}
