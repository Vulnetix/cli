package tea

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// jsonSeen returns v as the JSON wire format can carry it. encoding/json
// replaces invalid UTF-8 in strings with U+FFFD and omits empty slices
// marked omitempty, so a value fresh from testing/quick is not a fixed point
// of Marshal/Unmarshal for reasons that have nothing to do with the shapes
// under test. Reading a value back once makes it one, and the properties
// below can then assert exact preservation of everything else.
func jsonSeen[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// plainComponentReleaseDetail is ComponentReleaseDetail without its
// UnmarshalJSON, so sanitising an input never runs the code under test.
type plainComponentReleaseDetail ComponentReleaseDetail

// flatComponentReleaseDetail is the 1.0.0 wire shape: the release's own
// fields at the top level, no "release" wrapper.
type flatComponentReleaseDetail struct {
	Release
	Distributions    []Distribution `json:"distributions,omitempty"`
	LatestCollection Collection     `json:"latestCollection"`
}

// TestComponentReleaseDetailRoundTrip checks that the wrapped shape
// json.Marshal emits (the one --json prints) reads back through
// UnmarshalJSON without losing the release, its distributions, or the
// latest collection.
func TestComponentReleaseDetailRoundTrip(t *testing.T) {
	f := func(d ComponentReleaseDetail) bool {
		in := jsonSeen(plainComponentReleaseDetail(d))
		b, err := json.Marshal(ComponentReleaseDetail(in))
		if err != nil {
			t.Errorf("marshal: %v", err)
			return false
		}
		var got ComponentReleaseDetail
		if err := json.Unmarshal(b, &got); err != nil {
			t.Errorf("unmarshal: %v", err)
			return false
		}
		return reflect.DeepEqual(got.Release.Release, in.Release.Release) &&
			reflect.DeepEqual(got.Release.Distributions, in.Release.Distributions) &&
			reflect.DeepEqual(got.LatestCollection, in.LatestCollection)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestComponentReleaseDetailFlatShape checks the 1.0.0 shape: JSON with the
// release's fields at the top level and no "release" object decodes into
// d.Release with LatestCollection set.
func TestComponentReleaseDetailFlatShape(t *testing.T) {
	f := func(r Release, dists []Distribution, c Collection) bool {
		in := jsonSeen(flatComponentReleaseDetail{Release: r, Distributions: dists, LatestCollection: c})
		b, err := json.Marshal(in)
		if err != nil {
			t.Errorf("marshal: %v", err)
			return false
		}
		var got ComponentReleaseDetail
		if err := json.Unmarshal(b, &got); err != nil {
			t.Errorf("unmarshal: %v", err)
			return false
		}
		return reflect.DeepEqual(got.Release.Release, in.Release) &&
			reflect.DeepEqual(got.Release.Distributions, in.Distributions) &&
			reflect.DeepEqual(got.LatestCollection, in.LatestCollection)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestFileMappersAreTotal checks that both mappers answer every filename,
// empty and mixed-case included, from a fixed vocabulary, and that case
// does not change the answer.
func TestFileMappersAreTotal(t *testing.T) {
	mediaTypes := map[string]bool{
		"application/vnd.cyclonedx+json": true,
		"application/spdx+json":          true,
		"application/sarif+json":         true,
		"application/vnd.openvex+json":   true,
		"application/json":               true,
		"text/plain":                     true,
		"application/octet-stream":       true,
	}
	artifactTypes := map[string]bool{
		"VULNERABILITIES": true,
		"BOM":             true,
		"ATTESTATION":     true,
		"RELEASE_NOTES":   true,
		"LICENSE":         true,
		"OTHER":           true,
	}
	f := func(name string) bool {
		return mediaTypes[MediaTypeForFile(name)] && artifactTypes[ArtifactTypeForFile(name)]
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
	for _, name := range []string{"", "BOM.CDX.JSON", "Results.SARIF", "license.TXT"} {
		if !f(name) {
			t.Errorf("%q: mapper returned a value outside the vocabulary", name)
		}
		// Case must not change the answer: a mixed-case name maps exactly as
		// its lower-case spelling does.
		lower := strings.ToLower(name)
		if got, want := MediaTypeForFile(name), MediaTypeForFile(lower); got != want {
			t.Errorf("MediaTypeForFile(%q) = %q, want %q (as for %q)", name, got, want, lower)
		}
		if got, want := ArtifactTypeForFile(name), ArtifactTypeForFile(lower); got != want {
			t.Errorf("ArtifactTypeForFile(%q) = %q, want %q (as for %q)", name, got, want, lower)
		}
	}
}
