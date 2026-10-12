package tea

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The vectors file is shared with the website and vdb-site. All three must
// agree on the order, because a client that ranks differently would choose a
// different version of the same publisher.
func TestRankCandidatesMatchesSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/tea-selection-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name      string              `json:"name"`
			Supported []string            `json:"supported"`
			Endpoints []WellKnownEndpoint `json:"endpoints"`
			Roots     []string            `json:"roots"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no vectors")
	}

	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := []string{}
			for _, cand := range RankCandidates(&WellKnown{SchemaVersion: 1, Endpoints: c.Endpoints}, c.Supported) {
				got = append(got, cand.Root())
			}
			want := c.Roots
			if want == nil {
				want = []string{}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("roots = %v, want %v", got, want)
			}
		})
	}
}

// 1.0.0 is the default: when a publisher offers both, it is chosen, and the
// older root stays on the list as the fallback.
func TestRootFromPrefersTheDefaultVersion(t *testing.T) {
	low, high := 0.2, 0.9
	doc := &WellKnown{
		SchemaVersion: 1,
		Endpoints: []WellKnownEndpoint{
			{URL: "https://low.example.com", Versions: []string{"1.0.0"}, Priority: &low},
			{URL: "https://high.example.com", Versions: []string{"0.4.0", "1.0.0", "1.1.0-beta.1"}, Priority: &high},
		},
	}
	if got := RootFrom(doc); got != "https://high.example.com/v1.0.0" {
		t.Errorf("got %q, want the higher-priority endpoint at 1.0.0", got)
	}
	want := []string{
		"https://high.example.com/v1.0.0",
		"https://low.example.com/v1.0.0",
		"https://high.example.com/v0.4.0",
	}
	if got := RootsFrom(doc); !reflect.DeepEqual(got, want) {
		t.Errorf("RootsFrom = %v, want %v", got, want)
	}
	if got := RootFrom(nil); got != "" {
		t.Errorf("a nil document produced %q", got)
	}
}

func TestRootFromRefusesAProviderWithNothingInCommon(t *testing.T) {
	doc := &WellKnown{SchemaVersion: 1, Endpoints: []WellKnownEndpoint{
		{URL: "https://x.example.com", Versions: []string{"2.0.0", "1.1.0-beta.1"}},
	}}
	if got := RootFrom(doc); got != "" {
		t.Errorf("got %q for a provider offering only versions this client does not speak", got)
	}
	if got := AdvertisedVersions(doc); !reflect.DeepEqual(got, []string{"2.0.0", "1.1.0-beta.1"}) {
		t.Errorf("AdvertisedVersions = %v", got)
	}
}

func TestVersionFromRoot(t *testing.T) {
	cases := map[string]string{
		"https://x.example.com/tea/v1.0.0":       "1.0.0",
		"https://x.example.com/tea/v1.0.0/":      "1.0.0",
		"https://x.example.com/v0.4.0":           "0.4.0",
		"https://x.example.com/v0.4":             "0.4.0",
		"https://x.example.com/v1.0.0+build.5":   "1.0.0",
		"https://x.example.com/tea/v1":           "",
		"https://x.example.com/tea/public/v1":    "",
		"https://x.example.com/custom":           "",
		"https://x.example.com/v1.0.0-rc.1/more": "",
	}
	for in, want := range cases {
		if got := VersionFromRoot(in); got != want {
			t.Errorf("VersionFromRoot(%q) = %q, want %q", in, got, want)
		}
	}
}
