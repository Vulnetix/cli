package main

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

func TestFeedSourcesReadsEveryReferenceForm(t *testing.T) {
	site := &uplink.Client{Endpoint: "https://site.example/api/site/", Authorization: func() string { return "Sensor d:s" }}
	refs := []string{
		"https://vulnetix.com/feeds/6f1c7a3e-2b4d-4e8f-9a0b-1c2d3e4f5a6b/0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
		"catalog:phishing-army",
		"org:6f1c7a3e-2b4d-4e8f-9a0b-1c2d3e4f5a6b",
		"org:not-a-uuid",
		"ftp://elsewhere/feed",
		"just words",
		"",
	}
	got := feedSources(refs, nil, site)
	if len(got) != 3 {
		t.Fatalf("sources = %d (%+v), want 3", len(got), got)
	}
	if s, ok := got[0].(*feed.Source); !ok || s.BaseURL != refs[0] {
		t.Fatalf("source 0 = %#v", got[0])
	}
	for i, ref := range refs[1:3] {
		ind, ok := got[i+1].(*feed.Indicators)
		if !ok || ind.Reference != ref || ind.Endpoint != "https://site.example/api/site" || ind.Authorization() != "Sensor d:s" {
			t.Fatalf("source %d = %#v", i+1, got[i+1])
		}
	}

	// With no uplink there is no credential to fetch the site's lists with.
	offline := feedSources(refs, nil, nil)
	if len(offline) != 1 || offline[0].Ref() != refs[0] {
		t.Fatalf("offline sources = %+v", offline)
	}
}
