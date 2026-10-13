package versions

import "testing"

func TestPEP440ParsesAndOrders(t *testing.T) {
	// Ascending, per PEP 440.
	order := []string{
		"3.2.0.dev0", "3.2.0a1", "3.2.0a2", "3.2.0b1", "3.2.0rc1", "3.2.0rc2",
		"3.2.0", "3.2.0.post1", "3.2.0.post2", "3.2.1.dev1", "3.2.1",
	}
	for i, s := range order {
		if _, err := Parse(s); err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if i == 0 {
			continue
		}
		a, _ := Parse(order[i-1])
		b, _ := Parse(s)
		if Compare(a, b) >= 0 {
			t.Errorf("%s should sort below %s", order[i-1], s)
		}
	}
}

func TestPEP440Spellings(t *testing.T) {
	equal := [][2]string{
		{"1.0.0rc1", "1.0.0.rc.1"},
		{"2.0alpha3", "2.0.0a3"},
		{"2.0beta1", "2.0b1"},
		{"1.0.0c1", "1.0.0rc1"},
		{"1.0.0_beta2", "1.0.0b2"},
	}
	for _, p := range equal {
		a, err1 := Parse(p[0])
		b, err2 := Parse(p[1])
		if err1 != nil || err2 != nil {
			t.Errorf("%q / %q: %v %v", p[0], p[1], err1, err2)
			continue
		}
		if Compare(a, b) != 0 {
			t.Errorf("%q and %q should be equal", p[0], p[1])
		}
	}
}

// Plain versions keep parsing exactly as before, and the original text is kept.
func TestPEP440DoesNotDisturbPlainVersions(t *testing.T) {
	for _, s := range []string{"1.2.3", "1.2", "2023.7.22", "1.0.0-rc.1", "1.0.0-rc1", "1.0.0-beta", "1.0.0-1", "5.3.2+local", "v1.2.3"} {
		if _, ok := pep440ToSemver(s); ok {
			t.Errorf("%q is not PEP 440-specific", s)
		}
	}
	v, err := Parse("3.2.0.dev0")
	if err != nil || v.Original != "3.2.0.dev0" {
		t.Errorf("original text must be preserved: %+v %v", v, err)
	}
	// A dev release of the next version is below its release but above the last one.
	dev, _ := Parse("3.2.0.dev0")
	prev, _ := Parse("3.1.9")
	rel, _ := Parse("3.2.0")
	if !(Compare(prev, dev) < 0 && Compare(dev, rel) < 0) {
		t.Error("3.1.9 < 3.2.0.dev0 < 3.2.0")
	}
}
