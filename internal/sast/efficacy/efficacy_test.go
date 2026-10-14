package efficacy

import (
	"regexp"
	"testing"
)

const (
	rulesDir   = "../rules"
	casesDir   = "../testdata/efficacy"
	catalogDir = "../secretsgen/catalog.json"
)

// TestCases runs every fixture case under testdata/efficacy through the
// production engine: each rule must report exactly the marked lines.
func TestCases(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates every rule's cases")
	}
	rules, err := LoadRules(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadCases(casesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		c := c
		t.Run(c.Rule+"/"+c.Name, func(t *testing.T) {
			t.Parallel()
			if r := RunCase(rules, c); !r.Pass() {
				t.Error(Describe(r))
			}
		})
	}
}

// TestSecretsCatalog proves every generated secret rule reports realistic
// random tokens of its own shape and that its placeholder and entropy gates
// reject what they should.
func TestSecretsCatalog(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates every generated secret rule")
	}
	rules, err := LoadRules(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := LoadCatalog(catalogDir)
	if err != nil {
		t.Fatal(err)
	}
	checks, err := CheckSecretsCatalog(rules, entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Verdict == VerdictFail {
			t.Errorf("%s %s: %v", c.Rule, c.Name, c.Problems)
		}
	}
}

func TestSampleMatchesItsPattern(t *testing.T) {
	patterns := []string{
		`\b(cfk_[A-Za-z0-9_-]{32,})\b`,
		`(?i)cohere[a-z0-9_]*\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?`,
		`\b(00[a-zA-Z0-9]{13}![A-Za-z0-9._]{96,})`,
		`\b(cf(?:ut|at)_[A-Za-z0-9_-]{32,})\b`,
		`(?i)postmark[a-z0-9_-]*\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`,
		`^(sk_live_[0-9a-zA-Z]{24,})$`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		for v := 0; v < 8; v++ {
			for _, mode := range []genMode{modeHigh, modeRandom, modeLowEntropy, modePlaceholder} {
				full, grp, err := SampleMode(p, v, mode)
				if err != nil {
					t.Fatalf("%s mode %d: %v", p, mode, err)
				}
				if !re.MatchString(full) || grp == "" {
					t.Fatalf("%s mode %d: sample %q does not match", p, mode, full)
				}
			}
		}
	}
}

func TestSampleExercisesAlternatives(t *testing.T) {
	seen := map[string]bool{}
	for v := 0; v < 12; v++ {
		full, _, err := SampleMode(`\b(cf(?:ut|at)_[A-Za-z0-9]{32})\b`, v, modeRandom)
		if err != nil {
			t.Fatal(err)
		}
		seen[full[:5]] = true
	}
	if !seen["cfut_"] || !seen["cfat_"] {
		t.Fatalf("both branches of the alternation should be sampled, got %v", seen)
	}
}

func TestStripMarkers(t *testing.T) {
	clean, want := StripMarkers("a\n~>b\nc\n~>\td")
	if clean != "a\nb\nc\n\td" || len(want) != 2 || want[0] != 2 || want[1] != 4 {
		t.Fatalf("got %q %v", clean, want)
	}
}

func TestExpandSamples(t *testing.T) {
	out, err := ExpandSamples("~>key = \"@@sample:AKIA[A-Z2-7]{16}@@\"\nother", "a.env")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^~>key = "AKIA[A-Z2-7]{16}"\nother$`).MatchString(out) {
		t.Fatalf("got %q", out)
	}
	again, _ := ExpandSamples("~>key = \"@@sample:AKIA[A-Z2-7]{16}@@\"\nother", "a.env")
	if again != out {
		t.Fatal("expansion must be deterministic")
	}
}
