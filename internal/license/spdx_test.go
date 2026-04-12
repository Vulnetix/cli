package license

import "testing"

func TestLookupSPDX(t *testing.T) {
	tests := []struct {
		id       string
		wantName string
		wantNil  bool
	}{
		{"MIT", "MIT License", false},
		{"Apache-2.0", "Apache License 2.0", false},
		{"GPL-3.0-only", "GNU General Public License v3.0 only", false},
		{"mit", "MIT License", false}, // case-insensitive
		{"NONEXISTENT-999", "", true},
	}
	for _, tt := range tests {
		rec := LookupSPDX(tt.id)
		if tt.wantNil {
			if rec != nil {
				t.Errorf("LookupSPDX(%q) = %v, want nil", tt.id, rec)
			}
			continue
		}
		if rec == nil {
			t.Fatalf("LookupSPDX(%q) = nil, want non-nil", tt.id)
		}
		if rec.Name != tt.wantName {
			t.Errorf("LookupSPDX(%q).Name = %q, want %q", tt.id, rec.Name, tt.wantName)
		}
	}
}

func TestLookupSPDX_Categories(t *testing.T) {
	tests := []struct {
		id       string
		wantCat  Category
	}{
		{"MIT", CategoryPermissive},
		{"Apache-2.0", CategoryPermissive},
		{"GPL-3.0-only", CategoryStrongCopyleft},
		{"LGPL-2.1-only", CategoryWeakCopyleft},
		{"MPL-2.0", CategoryWeakCopyleft},
		{"CC0-1.0", CategoryPublicDomain},
		{"AGPL-3.0-only", CategoryStrongCopyleft},
	}
	for _, tt := range tests {
		rec := LookupSPDX(tt.id)
		if rec == nil {
			t.Fatalf("LookupSPDX(%q) = nil", tt.id)
		}
		if rec.Category != tt.wantCat {
			t.Errorf("LookupSPDX(%q).Category = %q, want %q", tt.id, rec.Category, tt.wantCat)
		}
	}
}

func TestParseSPDXExpression(t *testing.T) {
	tests := []struct {
		expr string
		want []string
	}{
		{"MIT", []string{"MIT"}},
		{"MIT OR Apache-2.0", []string{"MIT", "Apache-2.0"}},
		{"GPL-2.0-only WITH Classpath-exception-2.0", []string{"GPL-2.0-only"}},
		{"(MIT OR Apache-2.0) AND BSD-3-Clause", []string{"MIT", "Apache-2.0", "BSD-3-Clause"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := ParseSPDXExpression(tt.expr)
		if len(got) != len(tt.want) {
			t.Errorf("ParseSPDXExpression(%q) = %v, want %v", tt.expr, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ParseSPDXExpression(%q)[%d] = %q, want %q", tt.expr, i, got[i], tt.want[i])
			}
		}
	}
}

func TestAllLicenses_NotEmpty(t *testing.T) {
	all := AllLicenses()
	if len(all) < 500 {
		t.Errorf("AllLicenses() returned %d entries, expected 500+", len(all))
	}
}
