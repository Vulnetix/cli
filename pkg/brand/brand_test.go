package brand

import "testing"

func TestHostVulnesis(t *testing.T) {
	cases := []struct{ in, want string }{
		{"vulnetix.com", "vulnes.is"},
		{"www.vulnetix.com", "www.vulnes.is"},
		{"packages.vulnetix.com", "packages.vulnes.is"},
		{"guardrails.vulnetix.com", "guardrails.vulnes.is"},
		{"docs.vulnetix.com", "docs.vulnes.is"},
		{"mcp.vulnetix.com", "mcp.vulnes.is"},
		{"cli.vulnetix.com", "cli.vulnes.is"},
		{"ingest.vulnetix.com", "ingest.vulnes.is"},
		{"api.vdb.vulnetix.com", "api-vdb.vulnes.is"},
		{"a.b.c.vulnetix.com", "a-b-c.vulnes.is"},
		{"API.VDB.Vulnetix.COM", "api-vdb.vulnes.is"},
		{"packages.vulnetix.com:443", "packages.vulnes.is:443"},
		{"vulnetix.com:8080", "vulnes.is:8080"},
		{"www.vulnetix.com.", "www.vulnes.is."},
		// Not ours: unchanged.
		{"", ""},
		{"example.com", "example.com"},
		{"notvulnetix.com", "notvulnetix.com"},
		{"vulnetix.com.evil.example", "vulnetix.com.evil.example"},
		{"vulnetix.co", "vulnetix.co"},
		{"vulnes.is", "vulnes.is"},
		{"www.vulnes.is", "www.vulnes.is"},
		{".vulnetix.com", ".vulnetix.com"},
		{"a..vulnetix.com", "a..vulnetix.com"},
		{"[::1]:443", "[::1]:443"},
		{"::1", "::1"},
	}
	for _, c := range cases {
		if got := Vulnesis.Host(c.in); got != c.want {
			t.Errorf("Vulnesis.Host(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestURLVulnesis(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://vulnetix.com", "https://vulnes.is"},
		{"https://vulnetix.com/", "https://vulnes.is/"},
		{"https://www.vulnetix.com", "https://www.vulnes.is"},
		{"https://packages.vulnetix.com", "https://packages.vulnes.is"},
		{"https://api.vdb.vulnetix.com/v1", "https://api-vdb.vulnes.is/v1"},
		{"https://www.vulnetix.com/resolve/billing#addons", "https://www.vulnes.is/resolve/billing#addons"},
		{"https://guardrails.vulnetix.com/{providerSlug}/{orgUuid}/v1", "https://guardrails.vulnes.is/{providerSlug}/{orgUuid}/v1"},
		{"https://docs.vulnetix.com/cli/authentication/storage/#no-keychain", "https://docs.vulnes.is/cli/authentication/storage/#no-keychain"},
		{"https://www.vulnetix.com/tea/v1.0.0?x=vulnetix.com&y=%2Fa", "https://www.vulnes.is/tea/v1.0.0?x=vulnetix.com&y=%2Fa"},
		{"https://www.vulnetix.com/a%20b/%zz", "https://www.vulnes.is/a%20b/%zz"},
		{"https://www.vulnetix.com?q=1", "https://www.vulnes.is?q=1"},
		{"https://www.vulnetix.com#frag", "https://www.vulnes.is#frag"},
		{"https://api.vdb.vulnetix.com:8443/v2", "https://api-vdb.vulnes.is:8443/v2"},
		{"https://user:pass@packages.vulnetix.com/npm", "https://user:pass@packages.vulnes.is/npm"},
		{"HTTPS://WWW.VULNETIX.COM/Pricing", "HTTPS://www.vulnes.is/Pricing"},
		{"http://vulnetix.com/x", "http://vulnes.is/x"},
		{"//cli.vulnetix.com/install.sh", "//cli.vulnes.is/install.sh"},
		{"wss://mcp.vulnetix.com/mcp", "wss://mcp.vulnes.is/mcp"},
		// Not ours, or not a URL: unchanged.
		{"", ""},
		{"https://example.com/vulnetix.com", "https://example.com/vulnetix.com"},
		{"https://vulnetix.com.example.org/", "https://vulnetix.com.example.org/"},
		{"https://notvulnetix.com/", "https://notvulnetix.com/"},
		{"https://user@vulnetix.com:pass@example.com/", "https://user@vulnetix.com:pass@example.com/"},
		{"https://[::1]:8080/", "https://[::1]:8080/"},
		{"http://localhost:8787", "http://localhost:8787"},
		{"vulnetix.com", "vulnetix.com"},
		{"www.vulnetix.com/pricing", "www.vulnetix.com/pricing"},
		{"vulnetix.com/v1", "vulnetix.com/v1"},
		{"urn:tei:uuid:vulnetix.com:abc", "urn:tei:uuid:vulnetix.com:abc"},
		{"tei://vulnetix.com/uuid/abc", "tei://vulnes.is/uuid/abc"},
		{"://vulnetix.com", "://vulnetix.com"},
		{"ht tp://vulnetix.com", "ht tp://vulnetix.com"},
		{"https://vulnetix.com:port/", "https://vulnetix.com:port/"},
		{"https://vul netix.com/", "https://vul netix.com/"},
		{"https://", "https://"},
		{"not a url", "not a url"},
	}
	for _, c := range cases {
		if got := Vulnesis.URL(c.in); got != c.want {
			t.Errorf("Vulnesis.URL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVulnetixIsIdentity(t *testing.T) {
	for _, s := range []string{
		"https://api.vdb.vulnetix.com/v1",
		"https://www.vulnetix.com",
		"vulnetix.com",
		"packages.vulnetix.com",
		"Docs: https://docs.vulnetix.com/cli/",
		"",
		"%%%",
	} {
		if got := Vulnetix.URL(s); got != s {
			t.Errorf("Vulnetix.URL(%q) = %q", s, got)
		}
		if got := Vulnetix.Host(s); got != s {
			t.Errorf("Vulnetix.Host(%q) = %q", s, got)
		}
		if got := Vulnetix.Text(s); got != s {
			t.Errorf("Vulnetix.Text(%q) = %q", s, got)
		}
	}
}

func TestTextVulnesis(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Docs: https://docs.vulnetix.com/cli/", "Docs: https://docs.vulnes.is/cli/"},
		{
			"see https://www.vulnetix.com/pricing, or https://api.vdb.vulnetix.com/v1.",
			"see https://www.vulnes.is/pricing, or https://api-vdb.vulnes.is/v1.",
		},
		{"(https://guardrails.vulnetix.com)", "(https://guardrails.vulnes.is)"},
		{"at https://vulnetix.com.", "at https://vulnes.is."},
		{"`https://cli.vulnetix.com/install.sh`", "`https://cli.vulnes.is/install.sh`"},
		{"machine packages.vulnetix.com", "machine packages.vulnetix.com"},
		{"apiVersion vulnetix.com/v1", "apiVersion vulnetix.com/v1"},
		{"urn:tei:purl:vulnetix.com:pkg:npm/lodash@4.17.20", "urn:tei:purl:vulnetix.com:pkg:npm/lodash@4.17.20"},
		{"https://example.com and https://www.vulnetix.com", "https://example.com and https://www.vulnes.is"},
	}
	for _, c := range cases {
		if got := Vulnesis.Text(c.in); got != c.want {
			t.Errorf("Vulnesis.Text(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Brand
		ok   bool
	}{
		{"vulnetix", Vulnetix, true},
		{"VULNETIX", Vulnetix, true},
		{"vulnesis", Vulnesis, true},
		{"Vulnesis", Vulnesis, true},
		{"  vulnesis\n", Vulnesis, true},
		{"", Vulnetix, false},
		{"vulnes.is", Vulnetix, false},
		{"acme", Vulnetix, false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Parse(%q) = %v, %v; want %v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNameStringDomain(t *testing.T) {
	if Vulnetix.Name() != "Vulnetix" || Vulnesis.Name() != "Vulnesis" {
		t.Fatalf("names: %q %q", Vulnetix.Name(), Vulnesis.Name())
	}
	if Vulnetix.String() != "vulnetix" || Vulnesis.String() != "vulnesis" {
		t.Fatalf("strings: %q %q", Vulnetix.String(), Vulnesis.String())
	}
	if Vulnetix.Domain() != "vulnetix.com" || Vulnesis.Domain() != "vulnes.is" {
		t.Fatalf("domains: %q %q", Vulnetix.Domain(), Vulnesis.Domain())
	}
	if Brand(42).Name() != "Vulnetix" {
		t.Fatalf("unknown brand must display as Vulnetix")
	}
}

func TestCurrentFromEnv(t *testing.T) {
	cases := []struct {
		name          string
		brand, alias  string
		want          Brand
		wantURLOutput string
	}{
		{"unset is vulnetix", "", "", Vulnetix, "https://api.vdb.vulnetix.com/v1"},
		{"explicit vulnetix", "vulnetix", "", Vulnetix, "https://api.vdb.vulnetix.com/v1"},
		{"vulnesis", "vulnesis", "", Vulnesis, "https://api-vdb.vulnes.is/v1"},
		{"case-insensitive", "VulNeSiS", "", Vulnesis, "https://api-vdb.vulnes.is/v1"},
		{"garbage is vulnetix", "acme-corp", "", Vulnetix, "https://api.vdb.vulnetix.com/v1"},
		{"alias", "", "vulnesis", Vulnesis, "https://api-vdb.vulnes.is/v1"},
		{"primary wins over alias", "vulnetix", "vulnesis", Vulnetix, "https://api.vdb.vulnetix.com/v1"},
		{"blank primary falls to alias", "  ", "VULNESIS", Vulnesis, "https://api-vdb.vulnes.is/v1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(EnvVar, c.brand)
			t.Setenv(AliasEnvVar, c.alias)
			Reset()
			t.Cleanup(Reset)
			if got := Current(); got != c.want {
				t.Fatalf("Current() = %v, want %v", got, c.want)
			}
			if got := URL("https://api.vdb.vulnetix.com/v1"); got != c.wantURLOutput {
				t.Fatalf("URL = %q, want %q", got, c.wantURLOutput)
			}
		})
	}
}

func TestCurrentReadsEnvOnce(t *testing.T) {
	t.Setenv(EnvVar, "vulnesis")
	Reset()
	t.Cleanup(Reset)
	if Current() != Vulnesis {
		t.Fatal("want Vulnesis")
	}
	t.Setenv(EnvVar, "vulnetix")
	if Current() != Vulnesis {
		t.Fatal("the environment must be read once")
	}
	Reset()
	if Current() != Vulnetix {
		t.Fatal("Reset must re-read the environment")
	}
}

func TestSetOverridesEnv(t *testing.T) {
	t.Setenv(EnvVar, "vulnetix")
	Reset()
	t.Cleanup(Reset)
	Set(Vulnesis)
	if Current() != Vulnesis {
		t.Fatal("Set(Vulnesis) not honoured")
	}
	if got := Host("www.vulnetix.com"); got != "www.vulnes.is" {
		t.Fatalf("Host = %q", got)
	}
	if got := Text("https://docs.vulnetix.com/x"); got != "https://docs.vulnes.is/x" {
		t.Fatalf("Text = %q", got)
	}
}
