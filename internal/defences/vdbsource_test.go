package defences

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// fakeAPI answers as POST /v2/defences/counts does, from real response bodies.
type fakeAPI struct {
	counts   string
	details  map[string]map[string]interface{}
	archives map[string][]byte
	archErr  error
	asked    [][]vdb.DefenceCountsItem
}

func (f *fakeAPI) V2DefenceCounts(items []vdb.DefenceCountsItem) (*vdb.DefenceCountsResponse, error) {
	f.asked = append(f.asked, items)
	var r vdb.DefenceCountsResponse
	if err := json.Unmarshal([]byte(f.counts), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (f *fakeAPI) V2VulnDefences(lane, id string) (map[string]interface{}, error) {
	if d, ok := f.details[lane+"|"+id]; ok {
		return d, nil
	}
	return map[string]interface{}{}, nil
}

func (f *fakeAPI) V2DefenceArchive(lane, uuid string) ([]byte, error) {
	if f.archErr != nil {
		return nil, f.archErr
	}
	return f.archives[lane+"|"+uuid], nil
}

const proCounts = `{"schemaVersion":"defence-counts/v1","tier":"pro","items":[
 {"key":"CVE-2025-1","resolved":{"kinds":["vulnId"],"vulnIds":["CVE-2025-1","GHSA-aaaa"]},
  "virtualPatches":{"total":2,"byKind":{"MODSECURITY":1,"NGINX":1},"hasMore":false,"defences":[
    {"uuid":"u1","kind":"MODSECURITY","title":"t1","deployMode":"log","confidence":"HIGH","falsePositiveRisk":"LOW","consoleUrl":"https://www.vulnetix.com/resolve/virtual-patching?dc=u1#catalogue"},
    {"uuid":"u2","kind":"NGINX","title":"t2","deployMode":"log","confidence":"MEDIUM","consoleUrl":"https://www.vulnetix.com/resolve/virtual-patching?dc=u2#catalogue"}]},
  "countermeasures":{"total":1,"byKind":{"SIGMA":1},"hasMore":false,"defences":[
    {"uuid":"u3","kind":"SIGMA","title":"t3","confidence":"MEDIUM","consoleUrl":"https://www.vulnetix.com/resolve/countermeasures?dc=u3#catalogue"}]}},
 {"key":"CVE-2025-2","virtualPatches":{"total":0,"byKind":{},"defences":[]},"countermeasures":{"total":0,"byKind":{},"defences":[]}},
 {"key":"PYSEC-2025-9","error":{"field":"vulnIds","message":"PYSEC-2025-9 is not a CVE, GHSA or CNVD identifier","status":400}}
]}`

// Below Pro the lanes' defences are null and the top level carries _entitlements.
const communityCounts = `{"schemaVersion":"defence-counts/v1","tier":"community","_entitlements":{"defences":"pro"},"items":[
 {"key":"CVE-2025-1","virtualPatches":{"total":2,"byKind":{"MODSECURITY":1,"NGINX":1},"hasMore":false,"defences":null},
  "countermeasures":{"total":1,"byKind":{"SIGMA":1},"hasMore":false,"defences":null}}]}`

func TestVDBSourceProCountsCarryRulesAndConsoleLinks(t *testing.T) {
	api := &fakeAPI{counts: proCounts}
	got, err := NewVDBSource(api).Lookup(context.Background(), []string{"CVE-2025-1", "CVE-2025-2", "PYSEC-2025-9"}, LookupOptions{Pro: true})
	if err != nil {
		t.Fatal(err)
	}

	s := got["CVE-2025-1"]
	if s.State != StateAvailable || s.Block.Count != 2 || s.Detect.Count != 1 {
		t.Fatalf("CVE-2025-1: %+v", s)
	}
	if len(s.Block.Rules) != 2 || s.Block.Rules[0].ConsoleURL != "https://www.vulnetix.com/resolve/virtual-patching?dc=u1#catalogue" {
		t.Errorf("console links should come through: %+v", s.Block.Rules)
	}
	if s.Block.ByKind[KindModSec] != 1 || s.Detect.ByKind[KindSigma] != 1 {
		t.Errorf("kinds: %+v %+v", s.Block.ByKind, s.Detect.ByKind)
	}
	if s.Block.Rules[0].DeployMode != "log" || s.Block.Rules[0].Confidence != "HIGH" {
		t.Errorf("rule fields: %+v", s.Block.Rules[0])
	}
	if got["CVE-2025-2"].State != StateNone {
		t.Errorf("an asked-and-empty answer is none, got %q", got["CVE-2025-2"].State)
	}
	if got["PYSEC-2025-9"].State != StateNotIndexed {
		t.Errorf("a refused identifier is not indexed, got %q", got["PYSEC-2025-9"].State)
	}

	if len(api.asked) != 1 || len(api.asked[0]) != 3 || api.asked[0][0].VulnIDs[0] != "CVE-2025-1" || api.asked[0][0].Key != "CVE-2025-1" {
		t.Errorf("one batched request keyed by id: %+v", api.asked)
	}
}

func TestVDBSourceCommunityGetsCountsAsGated(t *testing.T) {
	got, _ := NewVDBSource(&fakeAPI{counts: communityCounts}).Lookup(context.Background(), []string{"CVE-2025-1"}, LookupOptions{})
	s := got["CVE-2025-1"]
	if s.State != StateGated || s.Block.Count != 2 || s.Detect.Count != 1 || len(s.Block.Rules) != 0 {
		t.Fatalf("below Pro: counts only, never none: %+v", s)
	}
}

// With no client registered the build cannot ask, and says nothing rather than none.
func TestVDBSourceWithoutAClientIsUnavailableNotNone(t *testing.T) {
	got, err := (&vdbSource{}).Lookup(context.Background(), []string{"CVE-2025-1"}, LookupOptions{Pro: true})
	if err != nil || got["CVE-2025-1"].State != StateUnavailable {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestVDBSourceDetailAddsCoverageAndChecksum(t *testing.T) {
	api := &fakeAPI{counts: proCounts, details: map[string]map[string]interface{}{
		"virtual-patches|CVE-2025-1": {"virtual-patches": []interface{}{
			map[string]interface{}{"uuid": "u1", "artifactId": "VX-1", "kind": "MODSECURITY", "title": "t1",
				"deployMode": "log", "confidence": "HIGH", "falsePositiveRisk": "LOW",
				"coverageNotes": "Does not match encoded variants.", "bodyContentHash": "abc123", "exploitSource": "exploit-db"},
		}},
	}}
	got, _ := NewVDBSource(api).Lookup(context.Background(), []string{"CVE-2025-1"}, LookupOptions{Pro: true, Detail: true})
	var r Rule
	for _, x := range got["CVE-2025-1"].Block.Rules {
		if x.UUID == "u1" {
			r = x
		}
	}
	if r.CoverageNotes == "" || r.SHA256 != "abc123" || r.ArtifactID != "VX-1" || r.ExploitSource != "exploit-db" {
		t.Fatalf("detail should add coverage, checksum and provenance: %+v", r)
	}
	if r.ConsoleURL == "" {
		t.Error("the console link from the counts must survive the merge")
	}
	if len(got["CVE-2025-1"].Block.Rules) != 2 {
		t.Errorf("rules the detail page omitted must be kept: %+v", got["CVE-2025-1"].Block.Rules)
	}

	// Detail is not asked for unless wanted, or below Pro.
	api2 := &fakeAPI{counts: proCounts, details: api.details}
	got, _ = NewVDBSource(api2).Lookup(context.Background(), []string{"CVE-2025-1"}, LookupOptions{Pro: true})
	if got["CVE-2025-1"].Block.Rules[0].CoverageNotes != "" {
		t.Error("a scan must not pay for detail")
	}
}

func TestVDBSourceDownload(t *testing.T) {
	api := &fakeAPI{archives: map[string][]byte{"virtual-patches|u1": []byte("SecRule x")}}
	src := NewVDBSource(api)
	b, err := src.Download(context.Background(), Rule{UUID: "u1", ArtifactID: "VX-1", Kind: KindModSec, SHA256: "h"})
	if err != nil || string(b.Content) != "SecRule x" || b.FileName != "VX-1-modsecurity.conf" || b.SHA256 != "h" {
		t.Fatalf("%v %+v", err, b)
	}
	// A countermeasure goes to the other lane.
	api.archives["countermeasures|u3"] = []byte("title: x")
	if b, _ := src.Download(context.Background(), Rule{UUID: "u3", Kind: KindSigma}); string(b.Content) != "title: x" {
		t.Errorf("lane routing: %+v", b)
	}

	api.archErr = &vdb.PlanLockedError{Feature: "virtual-patches", RequiredPlan: "pro"}
	if _, err := src.Download(context.Background(), Rule{UUID: "u1", Kind: KindModSec}); err == nil || !strings.Contains(err.Error(), "Pro plan") {
		t.Errorf("a plan lock should say Pro: %v", err)
	}
	api.archErr = errors.New("boom")
	if _, err := src.Download(context.Background(), Rule{UUID: "u1", Kind: KindModSec}); err == nil {
		t.Error("errors must surface")
	}
	if _, err := src.Download(context.Background(), Rule{}); err == nil {
		t.Error("a rule with no id cannot be downloaded")
	}
}

type slowAPI struct{ fakeAPI }

func (s *slowAPI) V2DefenceCounts([]vdb.DefenceCountsItem) (*vdb.DefenceCountsResponse, error) {
	select {} // never answers
}

// A slow backend must cost the defence lines, not the scan.
func TestVDBSourceHonoursTheCallersDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*1000*1000) // 50ms
	defer cancel()
	_, err := NewVDBSource(&slowAPI{}).Lookup(ctx, []string{"CVE-2025-1"}, LookupOptions{})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
}
