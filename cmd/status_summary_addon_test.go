package cmd

import (
	"testing"

	pfw "github.com/vulnetix/cli/v4/pkg/packagefirewall"
)

func TestAddonRequires(t *testing.T) {
	npm, _ := pfw.ByCommand("npm")
	aur, _ := pfw.ByCommand("aur")
	goEco, _ := pfw.ByCommand("go")
	cases := []struct {
		name string
		eco  pfw.Ecosystem
		plan string
		want string
	}{
		{"free aur on community", aur, "COMMUNITY", ""},
		{"npm on community", npm, "COMMUNITY", "requires the Package Firewall add-on"},
		{"npm on pro", npm, "PRO", "requires the Package Firewall add-on"},
		{"npm on business", npm, "TEAMS", "requires the Package Firewall add-on"},
		{"go proxy on pro", goEco, "PRO", "requires the Package Firewall add-on"},
		{"npm on enterprise", npm, "ENTERPRISE", ""},
		{"npm on unknown plan", npm, "UNKNOWN", ""},
	}
	for _, c := range cases {
		if got := addonRequires(c.eco, c.plan); got != c.want {
			t.Errorf("%s: addonRequires = %q, want %q", c.name, got, c.want)
		}
	}
}
