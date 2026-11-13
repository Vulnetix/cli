package update

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// preReleaseAlphabet mixes the characters real tags use with the separators
// the parser has to cope with: dots, dashes and slashes inside a pre-release.
const preReleaseAlphabet = "abcdrcdevalphabeta0123456789.-/+_"

// Generate makes Version values the way a release tag would carry them:
// non-negative numeric parts and an optional free-form pre-release.
func (Version) Generate(r *rand.Rand, _ int) reflect.Value {
	v := Version{Major: r.Intn(1000), Minor: r.Intn(1000), Patch: r.Intn(1000)}
	if r.Intn(2) == 0 {
		var b strings.Builder
		for n := 1 + r.Intn(12); n > 0; n-- {
			b.WriteByte(preReleaseAlphabet[r.Intn(len(preReleaseAlphabet))])
		}
		v.PreRelease = b.String()
	}
	// Small ranges make equal parts, and so the pre-release comparison, common.
	if r.Intn(3) == 0 {
		v.Major, v.Minor, v.Patch = r.Intn(2), r.Intn(2), r.Intn(2)
	}
	return reflect.ValueOf(v)
}

// versionInput is an arbitrary string biased towards almost-versions, so the
// parser sees prefixes, missing and extra segments and non-numeric parts.
type versionInput string

func (versionInput) Generate(r *rand.Rand, _ int) reflect.Value {
	pieces := []string{"", "v", "1", "02", "10", ".", "..", "-", "rc1", "x", "+", " ", "/", "999999999999999999999"}
	var b strings.Builder
	for n := r.Intn(9); n > 0; n-- {
		b.WriteString(pieces[r.Intn(len(pieces))])
	}
	return reflect.ValueOf(versionInput(b.String()))
}

var quickConfig = &quick.Config{MaxCount: 5000}

// TestVersionRoundTrip: whatever String emits, ParseVersion reads back to the
// same Version.
func TestVersionRoundTrip(t *testing.T) {
	roundTrip := func(v Version) bool {
		got, err := ParseVersion(v.String())
		return err == nil && got == v
	}
	if err := quick.Check(roundTrip, quickConfig); err != nil {
		t.Error(err)
	}
}

// TestParsedVersionRoundTrip: any input ParseVersion accepts survives a trip
// through String unchanged.
func TestParsedVersionRoundTrip(t *testing.T) {
	roundTrip := func(in versionInput) bool {
		v, err := ParseVersion(string(in))
		if err != nil {
			return true
		}
		again, err := ParseVersion(v.String())
		return err == nil && again == v
	}
	if err := quick.Check(roundTrip, quickConfig); err != nil {
		t.Error(err)
	}
}

// TestParseVersionNeverPanics covers arbitrary strings as well as the biased
// almost-versions; either a Version or an error comes back.
func TestParseVersionNeverPanics(t *testing.T) {
	for _, s := range []string{"", "v", "1.2", "1.2.3.4", "v1.2.3-rc1", "a.b.c", "1.2.3-", "-1.2.3", "v-"} {
		_, _ = ParseVersion(s)
	}
	arbitrary := func(s string) bool { _, _ = ParseVersion(s); return true }
	if err := quick.Check(arbitrary, quickConfig); err != nil {
		t.Error(err)
	}
	biased := func(in versionInput) bool { _, _ = ParseVersion(string(in)); return true }
	if err := quick.Check(biased, quickConfig); err != nil {
		t.Error(err)
	}
}

// TestVersionCompareIsATotalOrder checks reflexivity, antisymmetry and
// transitivity, and that IsNewerThan agrees with Compare.
func TestVersionCompareIsATotalOrder(t *testing.T) {
	reflexive := func(a Version) bool { return a.Compare(a) == 0 }
	antisymmetric := func(a, b Version) bool {
		ab, ba := a.Compare(b), b.Compare(a)
		return ab == -ba && (ab == 0) == (a == b) && a.IsNewerThan(b) == (ab > 0)
	}
	transitive := func(a, b, c Version) bool {
		if a.Compare(b) <= 0 && b.Compare(c) <= 0 {
			return a.Compare(c) <= 0
		}
		return true
	}
	for name, prop := range map[string]any{"reflexive": reflexive, "antisymmetric": antisymmetric, "transitive": transitive} {
		if err := quick.Check(prop, quickConfig); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestVersionCompareNeverPanics includes values ParseVersion never produces
// (negative parts) alongside generated ones.
func TestVersionCompareNeverPanics(t *testing.T) {
	_ = Version{Major: -1, PreRelease: "a/b.c"}.Compare(Version{Major: -1})
	anyValues := func(a, b Version) bool { _ = a.Compare(b); return true }
	if err := quick.Check(anyValues, quickConfig); err != nil {
		t.Error(err)
	}
}
