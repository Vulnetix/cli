package defences

import (
	"context"
	"testing"
	"time"
)

func TestLaneOfNeverOverstates(t *testing.T) {
	if LaneOf(KindModSec) != LaneBlock || LaneOf(KindSigma) != LaneDetect {
		t.Fatal("known kinds mapped to the wrong lane")
	}
	// A format we do not recognise must not be presented as blocking.
	if LaneOf("SOMETHING_NEW") != LaneDetect {
		t.Fatal("an unknown kind must fall back to the weaker claim")
	}
}

func TestResolveIdentifier(t *testing.T) {
	if id, ok := Resolve("CVE-2024-1", "GHSA-x"); !ok || id != "CVE-2024-1" {
		t.Fatalf("got %q %v", id, ok)
	}
	// Any advisory family is looked up: the server widens it through its aliases.
	for _, id := range []string{"PYSEC-2024-38", "GO-2024-1", "RUSTSEC-2024-1", "GHSA-xxxx-yyyy-zzzz"} {
		if got, ok := Resolve(id); !ok || got != id {
			t.Errorf("%s should be looked up as it is: %q %v", id, got, ok)
		}
	}
	for _, id := range []string{"", "nonsense", "-2024-1", "CVE", "has space-1"} {
		if _, ok := Resolve(id); ok {
			t.Errorf("%q is not shaped like an advisory id", id)
		}
	}
}

func TestStubSourceSaysNothingRatherThanNone(t *testing.T) {
	got, err := Unavailable.Lookup(context.Background(), []string{"CVE-2024-1"}, LookupOptions{Pro: true})
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2024-1"].State != StateUnavailable {
		t.Fatalf("stub reported %q; reporting none would claim no defence exists", got["CVE-2024-1"].State)
	}
	if _, err := Unavailable.Download(context.Background(), Rule{}); err != ErrNotAvailable {
		t.Fatalf("Download = %v, want ErrNotAvailable", err)
	}
}

func TestStaticSourceWithholdsBodiesFromCommunity(t *testing.T) {
	src := StaticSource{Summaries: map[string]Summary{
		"CVE-2025-1": {
			Block: LaneSummary{Count: 1, ByKind: map[Kind]int{KindModSec: 1},
				Rules: []Rule{{UUID: "u1", Kind: KindModSec, ArchiveURL: "/v2/virtual-patches/u1/archive"}}},
		},
	}}

	pro, _ := src.Lookup(context.Background(), []string{"cve-2025-1"}, LookupOptions{Pro: true})
	if s := pro["cve-2025-1"]; s.State != StateAvailable || len(s.Block.Rules) != 1 {
		t.Fatalf("pro: %+v", s)
	}
	free, _ := src.Lookup(context.Background(), []string{"CVE-2025-1"}, LookupOptions{})
	if s := free["CVE-2025-1"]; s.State != StateGated || s.Block.Count != 1 || len(s.Block.Rules) != 0 {
		t.Fatalf("community should see counts and no rules: %+v", s)
	}
	none, _ := src.Lookup(context.Background(), []string{"CVE-2025-2"}, LookupOptions{Pro: true})
	if none["CVE-2025-2"].State != StateNone {
		t.Fatalf("unknown id: %+v", none["CVE-2025-2"])
	}
}

func TestControlExpiryAndEffect(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	live := Control{Lane: LaneBlock, Mode: "block", Until: now.Add(time.Hour)}
	if !live.Active(now) || !live.Blocks() {
		t.Fatal("a live blocking control should be active and blocking")
	}
	if (Control{Lane: LaneBlock, Mode: "log", Until: now.Add(time.Hour)}).Blocks() {
		t.Fatal("a log-only rule blocks nothing")
	}
	if (Control{Lane: LaneDetect, Until: now.Add(time.Hour)}).Blocks() {
		t.Fatal("a detection does not block")
	}
	if !(Control{Until: now.Add(-time.Second)}).Expired(now) {
		t.Fatal("a lapsed control should be expired")
	}
	if !(Control{}).Expired(now) {
		t.Fatal("a control with no expiry must not be treated as permanent")
	}
}

func TestControlsRoundTrip(t *testing.T) {
	root := t.TempDir()
	set, err := LoadControls(root)
	if err != nil || len(set.Controls) != 0 {
		t.Fatalf("missing file should be empty: %v %v", set, err)
	}
	set.Upsert(Control{VulnID: "CVE-1", Package: "a", Lane: LaneBlock, Where: "first"})
	set.Upsert(Control{VulnID: "cve-1", Package: "A", Lane: LaneBlock, Where: "second"})
	set.Upsert(Control{VulnID: "CVE-1", Package: "a", Lane: LaneDetect, Where: "siem"})
	if err := set.Save(root); err != nil {
		t.Fatal(err)
	}
	got, err := LoadControls(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Controls) != 2 {
		t.Fatalf("upsert should replace the same lane: %+v", got.Controls)
	}
	if n := len(got.For("CVE-1", "a")); n != 2 {
		t.Fatalf("For = %d", n)
	}
}
