package versions

// MIRRORED — this test corpus is kept byte-identical between
// vdb-api/internal/versions and cli/internal/versions. Update both copies
// together.

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"v0.5.0", "0.5.0"},
		{"V1.2.3", "1.2.3"},
		{"  1.2.3  ", "1.2.3"},
		{"npm:1.2.3", "1.2.3"},
		{"npm:v1.2.3", "1.2.3"},
		{"≥ 0.31.0 < 1.2.0", ">= 0.31.0 < 1.2.0"},
		{"≤ 2.0.0", "<= 2.0.0"},
		{"vault", "vault"}, // v not followed by digit survives
		{"", ""},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		v, err := Parse("1.2.3")
		if err != nil || v.Major != 1 || v.Minor != 2 || v.Patch != 3 {
			t.Fatalf("Parse(1.2.3) = %+v, %v", v, err)
		}
	})
	t.Run("v-prefix", func(t *testing.T) {
		v, err := Parse("v0.5.0")
		if err != nil || v.Major != 0 || v.Minor != 5 || v.Patch != 0 {
			t.Fatalf("Parse(v0.5.0) = %+v, %v", v, err)
		}
	})
	t.Run("two-part", func(t *testing.T) {
		v, err := Parse("1.2")
		if err != nil || v.Major != 1 || v.Minor != 2 || v.Patch != 0 {
			t.Fatalf("Parse(1.2) = %+v, %v", v, err)
		}
	})
	t.Run("four-part", func(t *testing.T) {
		v, err := Parse("2.5.1.7")
		if err != nil || v.Patch != 1 || len(v.Extra) != 1 || v.Extra[0] != 7 {
			t.Fatalf("Parse(2.5.1.7) = %+v, %v", v, err)
		}
	})
	t.Run("prerelease", func(t *testing.T) {
		v, err := Parse("9.3.0-beta")
		if err != nil || v.Prerelease != "beta" || v.IsPseudo {
			t.Fatalf("Parse(9.3.0-beta) = %+v, %v", v, err)
		}
	})
	t.Run("build-metadata", func(t *testing.T) {
		v, err := Parse("1.2.3+b42")
		if err != nil || v.Build != "b42" || v.Prerelease != "" {
			t.Fatalf("Parse(1.2.3+b42) = %+v, %v", v, err)
		}
	})
	t.Run("pseudo-zero-base", func(t *testing.T) {
		v, err := Parse("0.0.0-20220622213112-05595931fe9d")
		if err != nil || !v.IsPseudo || v.PseudoTimestamp != "20220622213112" || v.PseudoBase != "0.0.0" {
			t.Fatalf("Parse(pseudo) = %+v, %v", v, err)
		}
	})
	t.Run("pseudo-tagged-base", func(t *testing.T) {
		v, err := Parse("5.3.2-0.20260526213025-e8e5b83ca9a5")
		if err != nil || !v.IsPseudo || v.PseudoBase != "5.3.2" || v.PseudoTimestamp != "20260526213025" {
			t.Fatalf("Parse(pseudo) = %+v, %v", v, err)
		}
	})
	t.Run("wildcard", func(t *testing.T) {
		for _, s := range []string{"*", "x", "X"} {
			v, err := Parse(s)
			if err != nil || !v.Wildcard {
				t.Fatalf("Parse(%q) = %+v, %v", s, v, err)
			}
		}
	})
	t.Run("wildcard-segment", func(t *testing.T) {
		v, err := Parse("1.2.x")
		if err != nil || v.Major != 1 || v.Minor != 2 || v.Patch != 0 {
			t.Fatalf("Parse(1.2.x) = %+v, %v", v, err)
		}
		if !v.SegWildcard || v.SegWildcardAt != 2 {
			t.Fatalf("Parse(1.2.x) segment wildcard = %+v", v)
		}
	})
	t.Run("junk", func(t *testing.T) {
		for _, s := range []string{"", "unspecified", "n/a", "8.x before 8.5.3", "abc"} {
			if _, err := Parse(s); err == nil {
				t.Errorf("Parse(%q) should error", s)
			}
		}
	})
}

func TestCompare(t *testing.T) {
	// SemVer 2.0 §11 canonical chain.
	chain := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
	}
	for i := 0; i < len(chain)-1; i++ {
		a, errA := Parse(chain[i])
		b, errB := Parse(chain[i+1])
		if errA != nil || errB != nil {
			t.Fatalf("parse chain: %v %v", errA, errB)
		}
		if Compare(a, b) >= 0 {
			t.Errorf("Compare(%s, %s) should be < 0", chain[i], chain[i+1])
		}
		if Compare(b, a) <= 0 {
			t.Errorf("Compare(%s, %s) should be > 0", chain[i+1], chain[i])
		}
	}

	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.9.0", "1.10.0", -1}, // numeric, not lexicographic
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3+b1", "1.2.3+b2", 0}, // build metadata ignored
		{"9.3.0-beta", "9.3.0", -1},
		{"0.0.0-20220622213112-05595931fe9d", "0.5.0", -1},
		{"5.3.2-0.20260526213025-e8e5b83ca9a5", "5.3.2", -1}, // Go pseudo sorts before base
		{"5.3.2-0.20260526213025-e8e5b83ca9a5", "5.3.1", 1},
		{"1.2", "1.2.0", 0},
		{"2.5.1.7", "2.5.1", 1},
		{"2.5.1.7", "2.5.1.8", -1},
		{"*", "99.99.99", 0}, // wildcard equals anything
	}
	for _, c := range cases {
		a, errA := Parse(c.a)
		b, errB := Parse(c.b)
		if errA != nil || errB != nil {
			t.Fatalf("parse %q/%q: %v %v", c.a, c.b, errA, errB)
		}
		got := Compare(a, b)
		if (got < 0 && c.want >= 0) || (got > 0 && c.want <= 0) || (got == 0 && c.want != 0) {
			t.Errorf("Compare(%s, %s) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func TestEqualExact(t *testing.T) {
	mustParse := func(s string) Version {
		v, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		return v
	}
	cases := []struct {
		a, b   string
		policy PseudoPolicy
		want   bool
	}{
		{"v0.5.0", "0.5.0", PseudoStrict, true},
		{"1.2.3+b42", "1.2.3", PseudoStrict, true}, // build metadata never matters
		{"9.3.0-beta", "9.3.0", PseudoBaseEqual, false},
		{"9.3.0-beta", "9.3.0-beta", PseudoStrict, true},
		// The user's exact example: pseudo equals base outside Go, not within.
		{"5.3.2-0.20260526213025-e8e5b83ca9a5", "5.3.2", PseudoBaseEqual, true},
		{"5.3.2-0.20260526213025-e8e5b83ca9a5", "5.3.2", PseudoStrict, false},
		{"5.3.2", "5.3.2-0.20260526213025-e8e5b83ca9a5", PseudoBaseEqual, true}, // symmetric
		{"0.0.0-20220622213112-05595931fe9d", "0.0.0", PseudoBaseEqual, true},
		{"0.0.0-20220622213112-05595931fe9d", "0.0.0", PseudoStrict, false},
		{"5.3.2-0.20260526213025-e8e5b83ca9a5", "5.3.1", PseudoBaseEqual, false},
		{"*", "1.2.3", PseudoStrict, true},
		// Segment wildcards prefix-match: "8.x" covers the whole 8 line.
		{"8.2.0", "8.x", PseudoStrict, true},
		{"8.0.0", "8.x", PseudoStrict, true},
		{"9.0.0", "8.x", PseudoStrict, false},
		{"1.2.5", "1.2.x", PseudoStrict, true},
		{"1.3.0", "1.2.x", PseudoStrict, false},
	}
	for _, c := range cases {
		if got := EqualExact(mustParse(c.a), mustParse(c.b), c.policy); got != c.want {
			t.Errorf("EqualExact(%s, %s, %v) = %v, want %v", c.a, c.b, c.policy, got, c.want)
		}
	}
}

func TestResolvePseudoPolicy(t *testing.T) {
	if ResolvePseudoPolicy(Options{Ecosystem: "go"}) != PseudoStrict {
		t.Error("go ecosystem should default to PseudoStrict")
	}
	if ResolvePseudoPolicy(Options{Ecosystem: "golang"}) != PseudoStrict {
		t.Error("golang ecosystem should default to PseudoStrict")
	}
	if ResolvePseudoPolicy(Options{Ecosystem: "npm"}) != PseudoBaseEqual {
		t.Error("npm ecosystem should default to PseudoBaseEqual")
	}
	if ResolvePseudoPolicy(Options{}) != PseudoBaseEqual {
		t.Error("empty ecosystem should default to PseudoBaseEqual")
	}
	strict := PseudoStrict
	if ResolvePseudoPolicy(Options{Ecosystem: "npm", PseudoPolicy: &strict}) != PseudoStrict {
		t.Error("explicit policy override should win")
	}
}

func TestParseRangeContains(t *testing.T) {
	cases := []struct {
		rng     string
		version string
		want    bool
	}{
		// Single operators at boundaries.
		{"= 1.5.0", "1.5.0", true},
		{"= 1.5.0", "1.5.1", false},
		{"1.5.0", "1.5.0", true}, // bare ⇒ exact
		{"< 3.0.0", "2.9.9", true},
		{"< 3.0.0", "3.0.0", false},
		{"<= 3.0.0", "3.0.0", true},
		{"<= 3.0.0", "3.0.1", false},
		{"> 1.0.0", "1.0.1", true},
		{"> 1.0.0", "1.0.0", false},
		{">= 1.0.0", "1.0.0", true},
		{">= 1.0.0", "0.9.9", false},
		{"!= 2.0.0", "2.0.1", true},
		{"!= 2.0.0", "2.0.0", false},
		// v-prefix tolerance both sides.
		{">= v1.0.0", "v1.2.3", true},
		{"= v0.5.0", "0.5.0", true},
		// AND group (space-separated).
		{">= 0.31.0 < 1.2.0", "0.31.0", true},
		{">= 0.31.0 < 1.2.0", "1.1.9", true},
		{">= 0.31.0 < 1.2.0", "1.2.0", false},
		{">= 0.31.0 < 1.2.0", "0.30.9", false},
		// Unicode operators.
		{"≥ 0.31.0 < 1.2.0", "0.31.0", true},
		{"≥ 0.31.0 < 1.2.0", "0.30.9", false},
		{"≤ 2.0.0", "2.0.0", true},
		// Comma with operators ⇒ AND.
		{">= 2.0.0, < 2.3.1", "2.1.0", true},
		{">= 2.0.0, < 2.3.1", "2.3.1", false},
		{">= 2.0.0, < 2.3.1", "1.9.0", false},
		// Bare comma list ⇒ OR exact list.
		{"1.14.1, 0.30.4", "0.30.4", true},
		{"1.14.1, 0.30.4", "1.14.1", true},
		{"1.14.1, 0.30.4", "0.30.5", false},
		{"1.14.1, 0.30.4", "1.14.2", false},
		// OR ranges.
		{"< 2.11.2 || >= 3.0.0 < 3.2.0", "2.11.1", true},
		{"< 2.11.2 || >= 3.0.0 < 3.2.0", "3.1.0", true},
		{"< 2.11.2 || >= 3.0.0 < 3.2.0", "2.12.0", false},
		// SaaS-style "< 2.11.2 >= 0" AND group.
		{"< 2.11.2 >= 0", "2.10.6", true},
		{"< 2.11.2 >= 0", "2.11.2", false},
		// ">= 0" includes prereleases of 0.0.0 (Go pseudo-versions).
		{">= 0 < 2.11.2", "0.0.0-20220622213112-05595931fe9d", true},
		// Interval notation.
		{"[2.0.0, 2.3.1)", "2.0.0", true},
		{"[2.0.0, 2.3.1)", "2.3.0", true},
		{"[2.0.0, 2.3.1)", "2.3.1", false},
		{"(2.0.0, 2.3.1]", "2.0.0", false},
		{"(2.0.0, 2.3.1]", "2.3.1", true},
		// Wildcards.
		{"*", "0.0.1", true},
		{"*", "99.99.99", true},
		{">= 0", "1.2.3", true},
		{">= 0.0.0", "0.0.1", true},
		// Prerelease within range (security posture: included).
		{">= 0.31.0 < 1.2.0", "1.2.0-beta", true},
		{"< 9.3.0", "9.3.0-beta", true},
		// Build metadata ignored.
		{"= 1.2.3", "1.2.3+b42", true},
		// Two-part versions.
		{">= 1.2", "1.2.0", true},
		// Segment wildcards in constraints prefix-match the whole line.
		{"8.x", "8.2.0", true},
		{"8.x", "8.0.0", true},
		{"8.x", "9.0.0", false},
		{"= 1.2.x", "1.2.7", true},
		{"= 1.2.x", "1.3.0", false},
	}
	for _, c := range cases {
		rs, err := ParseRange(c.rng)
		if err != nil {
			t.Errorf("ParseRange(%q) error: %v", c.rng, err)
			continue
		}
		v, err := Parse(c.version)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.version, err)
			continue
		}
		if got := rs.Contains(v, PseudoBaseEqual); got != c.want {
			t.Errorf("ParseRange(%q).Contains(%q) = %v, want %v", c.rng, c.version, got, c.want)
		}
	}
}

func TestParseRangeErrors(t *testing.T) {
	for _, s := range []string{"", "unspecified", "8.x before 8.5.3", ">= unspecified"} {
		if _, err := ParseRange(s); err == nil {
			t.Errorf("ParseRange(%q) should error", s)
		}
	}
}

func TestIsWildcardRange(t *testing.T) {
	for _, s := range []string{"*", ">= 0", ">= 0.0.0", "<= 99999", ">=0", " * "} {
		if !IsWildcardRange(s) {
			t.Errorf("IsWildcardRange(%q) should be true", s)
		}
	}
	for _, s := range []string{">= 1.0.0", "= 0", "1.2.3", ""} {
		if IsWildcardRange(s) {
			t.Errorf("IsWildcardRange(%q) should be false", s)
		}
	}
}
