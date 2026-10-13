package cmd

import (
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/display"
)

// The batched endpoint returns reference rows keyed by id. The renderer reads
// {identifier, advisories}. A mismatch is what printed "Advisories for" and then
// "No advisories found" for Log4Shell.
func TestAdvisoriesResultShapesBatchedRows(t *testing.T) {
	rows := []any{
		map[string]any{"url": "https://example.invalid/a", "referenceSource": "vendor", "tags": []any{"patch"}},
		map[string]any{"url": "https://example.invalid/b", "referenceSource": "mailing-list"},
	}
	got := advisoriesResult("CVE-2021-44228", rows)
	if got["identifier"] != "CVE-2021-44228" {
		t.Fatalf("identifier = %v", got["identifier"])
	}
	advs, _ := got["advisories"].([]any)
	if len(advs) != 2 {
		t.Fatalf("advisories = %v", got["advisories"])
	}
	first := advs[0].(map[string]any)
	if first["url"] != "https://example.invalid/a" || first["source"] != "vendor" {
		t.Errorf("first = %v", first)
	}

	out := display.RenderAdvisories(got, &display.Context{Term: &display.Terminal{Width: 100}})
	for _, want := range []string{"Advisories for CVE-2021-44228", "https://example.invalid/a", "[vendor]"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// An empty answer still says what was asked, and does not claim more than it
// knows.
func TestAdvisoriesResultWhenNothingIsReturned(t *testing.T) {
	got := advisoriesResult("CVE-2021-44228", nil)
	if got["identifier"] != "CVE-2021-44228" {
		t.Fatalf("an empty result must still carry the identifier: %v", got)
	}
	out := display.RenderAdvisories(got, &display.Context{Term: &display.Terminal{Width: 100}})
	if !strings.Contains(out, "Advisories for CVE-2021-44228") || !strings.Contains(out, "No advisories were returned for CVE-2021-44228") {
		t.Errorf("the empty case should name the id:\n%s", out)
	}
	if strings.Contains(out, "No advisories found") {
		t.Errorf("'found' claims the database was searched and has none:\n%s", out)
	}
	if !strings.Contains(out, "osv.dev/vulnerability/CVE-2021-44228") {
		t.Errorf("should point at where to look:\n%s", out)
	}
}

func TestPerVulnerabilityShapeIsKeptAndGainsItsIdentifier(t *testing.T) {
	legacy := map[string]any{"advisories": []any{map[string]any{"id": "GHSA-x", "url": "u"}}}
	got := advisoriesResult("CVE-1", legacy)
	if got["identifier"] != "CVE-1" || len(got["advisories"].([]any)) != 1 {
		t.Errorf("%v", got)
	}
	if w := workaroundsResult("CVE-1", nil); w["identifier"] != "CVE-1" {
		t.Errorf("%v", w)
	}
}

func TestRequireV2NamesTheWayOutNotAFlagToAdd(t *testing.T) {
	old := vdbAPIVersion
	defer func() { vdbAPIVersion = old }()

	vdbAPIVersion = "v2"
	if err := requireV2("advisories"); err != nil {
		t.Fatalf("v2 is the default and needs no flag: %v", err)
	}
	vdbAPIVersion = ""
	if err := requireV2("advisories"); err != nil {
		t.Fatalf("an empty version means the default, v2: %v", err)
	}
	vdbAPIVersion = "v1"
	err := requireV2("advisories")
	if err == nil {
		t.Fatal("v1 must be refused for a v2-only command")
	}
	for _, want := range []string{"only available on the v2 API", "Drop -V v1", "vulnetix vdb advisories <vuln-id>"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %q", want, err)
		}
	}
	if strings.Contains(err.Error(), "-V v2") {
		t.Errorf("the message must not ask for a flag nobody needs: %q", err)
	}
}

func TestCliAnswerPending(t *testing.T) {
	for name, c := range map[string]struct {
		data map[string]any
		want bool
	}{
		"the live placeholder": {map[string]any{"guidanceByCwe": map[string]any{}, "note": "cli.cwe-guidance backend wire-up pending — shape is stable"}, true},
		"an empty bag":         {map[string]any{"guidanceByCwe": map[string]any{}}, true},
		"missing bag":          {map[string]any{}, true},
		"a real answer":        {map[string]any{"guidanceByCwe": map[string]any{"CWE-502": []any{"x"}}}, false},
	} {
		if got := cliAnswerPending(c.data, "guidanceByCwe"); got != c.want {
			t.Errorf("%s: got %v want %v", name, got, c.want)
		}
	}
}
