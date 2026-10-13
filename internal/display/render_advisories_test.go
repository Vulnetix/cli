package display

import (
	"strings"
	"testing"
)

// The shape the v2 endpoint actually returns for CVE-2021-44228: sections, not
// an "advisories" array. The renderer used to look for the array, found none, and
// printed "No advisories found" for a vulnerability with hundreds of vendor
// patches.
func realAdvisoriesRecord() map[string]any {
	var patches []any
	for i := 0; i < 30; i++ {
		v := "ibm"
		if i%3 == 0 {
			v = "oracle"
		}
		patches = append(patches, map[string]any{"product": "p", "vendor": v, "source": "variot"})
	}
	return map[string]any{
		"identifier": "CVE-2021-44228",
		"state":      "PUBLISHED",
		"title":      "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
		"redhatAdvisories": []any{
			map[string]any{"errataUrl": "https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_1747.json",
				"initialReleaseDate": float64(1740355718), "currentReleaseDate": float64(1778797847),
				"products": []any{map[string]any{"status": "fixed"}, map[string]any{"status": "fixed"}}},
			map[string]any{"errataUrl": "https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_5093.json",
				"initialReleaseDate": float64(1639000000)},
		},
		"vendorPatches":  patches,
		"msrcPatches":    []any{},
		"solutions":      []any{},
		"vendorComments": []any{},
		"references": []any{
			map[string]any{"source": "vulncheck-nvd", "url": "http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html"},
		},
		"aiAdvisory": nil,
	}
}

func TestRenderAdvisoriesReadsTheRealShape(t *testing.T) {
	out := RenderAdvisories(realAdvisoriesRecord(), &Context{Term: &Terminal{Width: 100}})
	for _, want := range []string{
		"Advisories for CVE-2021-44228", "PUBLISHED",
		"Red Hat advisories", "RHSA-2025:1747", "released 2025-02-24", "2 products", "RHSA-2021:5093",
		"Vendor patches", "ibm (20)", "oracle (10)",
		"References", "packetstormsecurity.com", "[vulncheck-nvd]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "No advisories") {
		t.Errorf("a record with data must not say there is none:\n%s", out)
	}
	// Newest first.
	if strings.Index(out, "RHSA-2025:1747") > strings.Index(out, "RHSA-2021:5093") {
		t.Errorf("Red Hat advisories should be newest first:\n%s", out)
	}
	// Empty sections are omitted rather than printed as headings with nothing.
	for _, absent := range []string{"MSRC", "Solutions", "Vendor comments", "AI advisory"} {
		if strings.Contains(out, absent) {
			t.Errorf("empty section %q should not print:\n%s", absent, out)
		}
	}
}

func TestRenderAdvisoriesCapsLongSections(t *testing.T) {
	rec := realAdvisoriesRecord()
	var refs []any
	for i := 0; i < 20; i++ {
		refs = append(refs, map[string]any{"source": "s", "url": "https://example.invalid/" + strings.Repeat("x", i)})
	}
	rec["references"] = refs
	out := RenderAdvisories(rec, &Context{Term: &Terminal{Width: 100}})
	if !strings.Contains(out, "and 14 more") {
		t.Errorf("20 references with a cap of 6 should say '14 more':\n%s", out)
	}
}

func TestDateOfIgnoresTheAPIsSentinels(t *testing.T) {
	for _, v := range []any{float64(0), float64(-62135596800000), nil, "x"} {
		if d := dateOf(v); d != "" {
			t.Errorf("dateOf(%v) = %q, want empty: a sentinel is not a date", v, d)
		}
	}
	if d := dateOf(float64(1740355718000)); d != "2025-02-24" {
		t.Errorf("milliseconds: %q", d)
	}
}

func TestErrataID(t *testing.T) {
	if got := errataID("https://x/y/rhsa-2025_1747.json"); got != "RHSA-2025:1747" {
		t.Errorf("%q", got)
	}
}
