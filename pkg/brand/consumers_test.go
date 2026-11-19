package brand_test

import (
	"testing"

	"github.com/vulnetix/cli/v4/pkg/aifirewall"
	"github.com/vulnetix/cli/v4/pkg/auth"
	"github.com/vulnetix/cli/v4/pkg/brand"
	"github.com/vulnetix/cli/v4/pkg/packagefirewall"
	"github.com/vulnetix/cli/v4/pkg/tea"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// TestConsumersFollowBrand checks that the default endpoints of the public
// packages follow the brand, and stay exactly as they were under Vulnetix.
func TestConsumersFollowBrand(t *testing.T) {
	cases := []struct {
		brand                              brand.Brand
		vdbBase, machine, gateway, teaRoot string
		firewall                           string
	}{
		{brand.Vulnetix, "https://api.vdb.vulnetix.com", "packages.vulnetix.com", "guardrails.vulnetix.com", "https://www.vulnetix.com/tea/v1.0.0", "https://packages.vulnetix.com/npm"},
		{brand.Vulnesis, "https://api-vdb.vulnes.is", "packages.vulnes.is", "guardrails.vulnes.is", "https://www.vulnes.is/tea/v1.0.0", "https://packages.vulnes.is/npm"},
	}
	for _, c := range cases {
		t.Run(c.brand.String(), func(t *testing.T) {
			brand.Set(c.brand)
			t.Cleanup(brand.Reset)
			if got := vdb.NewClient("", "").BaseURL; got != c.vdbBase {
				t.Errorf("vdb base = %q, want %q", got, c.vdbBase)
			}
			if got := auth.PackageFirewallMachine(); got != c.machine {
				t.Errorf("netrc machine = %q, want %q", got, c.machine)
			}
			if got, err := aifirewall.GatewayHost(""); err != nil || got != c.gateway {
				t.Errorf("gateway host = %q, %v; want %q", got, err, c.gateway)
			}
			if got := tea.New("", nil).BaseURL; got != c.teaRoot {
				t.Errorf("tea root = %q, want %q", got, c.teaRoot)
			}
			if got := packagefirewall.ProxyURL("", packagefirewall.Ecosystem{Prefix: "npm"}); got != c.firewall {
				t.Errorf("firewall = %q, want %q", got, c.firewall)
			}
			// An explicit base always wins over the brand.
			if got := packagefirewall.ProxyURL("http://localhost:8080", packagefirewall.Ecosystem{}); got != "http://localhost:8080" {
				t.Errorf("explicit proxy overridden: %q", got)
			}
			pub, _ := tea.ServerForCatalogue(tea.CataloguePublic)
			if !tea.IsPublicServer(pub) || !tea.IsPublicServer(tea.PublicServer) {
				t.Errorf("public catalogue root %q not recognised", pub)
			}
		})
	}
}
