package packagefirewall

import (
	"strings"
	"testing"
)

func TestAllMatchesPlan(t *testing.T) {
	got := All()
	if len(got) != 23 {
		t.Fatalf("All() length = %d, want 23", len(got))
	}
	cases := map[string]struct {
		prefix string
		free   bool
	}{
		"go":        {"", false},
		"npm":       {"npm", false},
		"pypi":      {"pypi", false},
		"cargo":     {"cargo", false},
		"gem":       {"gem", false},
		"hex":       {"hex", false},
		"pub":       {"pub", false},
		"maven":     {"maven", false},
		"nuget":     {"nuget", false},
		"composer":  {"composer", false},
		"conan":     {"conan", false},
		"conda":     {"conda", false},
		"cran":      {"cran", false},
		"julia":     {"julia", false},
		"docker":    {"v2", false},
		"debian":    {"debian", false},
		"rpm":       {"rpm", false},
		"alpine":    {"alpine", false},
		"helm":      {"helm", false},
		"chef":      {"chef", false},
		"terraform": {"terraform", false},
		"homebrew":  {"homebrew", false},
	}
	for command, want := range cases {
		eco, ok := ByCommand(command)
		if !ok {
			t.Fatalf("ByCommand(%q) missing", command)
		}
		if eco.Prefix != want.prefix || eco.Free != want.free {
			t.Errorf("ByCommand(%q) = prefix %q free %v, want prefix %q free %v", command, eco.Prefix, eco.Free, want.prefix, want.free)
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

func TestOnlyGoDevAndAURAreFree(t *testing.T) {
	for _, eco := range All() {
		if want := eco.ID == "aur"; eco.Free != want {
			t.Errorf("%s: Free = %v, want %v", eco.ID, eco.Free, want)
		}
	}
	for id, want := range map[string]bool{"go-dev": true, "aur": true, "AUR": true, "go": false, "arch": false, "npm": false, "homebrew": false, "": false} {
		if got := IsFree(id); got != want {
			t.Errorf("IsFree(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestAddonNoteOnlyForAUR(t *testing.T) {
	aur, _ := ByCommand("aur")
	if note := AddonNote(aur); !strings.Contains(note, "/arch") || !strings.Contains(note, "requires the Package Firewall add-on") {
		t.Errorf("AddonNote(aur) = %q", note)
	}
	npm, _ := ByCommand("npm")
	if note := AddonNote(npm); note != "" {
		t.Errorf("AddonNote(npm) = %q, want empty", note)
	}
}
