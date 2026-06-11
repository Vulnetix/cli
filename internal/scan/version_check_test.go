package scan

import "testing"

func TestIsVersionAffected(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		rng       string
		ecosystem string
		want      bool
	}{
		// Conservative contract.
		{"empty range assumes affected", "1.0.0", "", "npm", true},
		{"unparseable installed assumes affected", "not-a-version!", "< 2.0.0", "npm", true},
		{"unparseable range assumes affected", "1.0.0", "8.x before 8.5.3", "npm", true},

		// Comma with operators ⇒ AND.
		{"comma AND in range", "2.1.0", ">= 2.0.0, < 2.3.1", "npm", true},
		{"comma AND upper exclusive", "2.3.1", ">= 2.0.0, < 2.3.1", "npm", false},
		{"comma AND below lower", "1.9.0", ">= 2.0.0, < 2.3.1", "npm", false},

		// Bare comma list ⇒ OR exact matches.
		{"bare comma list hit", "0.30.4", "1.14.1, 0.30.4", "npm", true},
		{"bare comma list other hit", "1.14.1", "1.14.1, 0.30.4", "npm", true},
		{"bare comma list miss", "0.30.5", "1.14.1, 0.30.4", "npm", false},

		// Interval notation.
		{"interval inclusive lower", "2.0.0", "[2.0.0, 2.3.1)", "npm", true},
		{"interval exclusive upper", "2.3.1", "[2.0.0, 2.3.1)", "npm", false},
		{"interval exclusive lower", "2.0.0", "(2.0.0, 2.3.1]", "npm", false},
		{"interval inclusive upper", "2.3.1", "(2.0.0, 2.3.1]", "npm", true},

		// Unicode operators.
		{"unicode gte in range", "0.31.0", "≥ 0.31.0 < 1.2.0", "npm", true},
		{"unicode gte below", "0.30.9", "≥ 0.31.0 < 1.2.0", "npm", false},
		{"unicode upper exclusive", "1.2.0", "≥ 0.31.0 < 1.2.0", "npm", false},

		// Exact match incl. v prefix.
		{"exact match", "2.3.1", "2.3.1", "npm", true},
		{"exact mismatch", "2.3.2", "2.3.1", "npm", false},
		{"v prefix installed", "v2.3.1", "2.3.1", "npm", true},
		{"v prefix range", "2.3.1", "= v2.3.1", "npm", true},

		// Wildcard and OR.
		{"wildcard", "9.9.9", "*", "npm", true},
		{"OR ranges first", "2.11.1", "< 2.11.2 || >= 3.0.0 < 3.2.0", "npm", true},
		{"OR ranges gap", "2.12.0", "< 2.11.2 || >= 3.0.0 < 3.2.0", "npm", false},

		// Build metadata and prereleases.
		{"build metadata equality", "1.2.3+b42", "= 1.2.3", "npm", true},
		{"prerelease inside range", "9.3.0-beta", "< 9.3.0", "npm", true},

		// Go pseudo-versions.
		{"pseudo in zero-lower range", "0.0.0-20220622213112-05595931fe9d", ">= 0 < 0.5.0", "go", true},
		{"pseudo before base go policy", "5.3.2-0.20260526213025-e8e5b83ca9a5", "= 5.3.2", "go", false},
		{"pseudo base-equal npm policy", "5.3.2-0.20260526213025-e8e5b83ca9a5", "= 5.3.2", "npm", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsVersionAffected(c.installed, c.rng, c.ecosystem); got != c.want {
				t.Errorf("IsVersionAffected(%q, %q, %q) = %v, want %v",
					c.installed, c.rng, c.ecosystem, got, c.want)
			}
		})
	}
}
