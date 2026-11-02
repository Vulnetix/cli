package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/suppress"
	"github.com/vulnetix/cli/v3/internal/vex"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

const testOpenVEX = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:x","author":"a","timestamp":"2026-01-01T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"status":"not_affected","justification":"component_not_present","products":[{"@id":"pkg:npm/a@1"}]}]}`

func TestBuildVEXIngestRequests(t *testing.T) {
	root := t.TempDir()
	git := &gitctx.GitContext{
		RepoRootPath:  root,
		RemoteURLs:    []string{"git@github.com:acme/widget.git"},
		CurrentCommit: "abc123",
	}
	docs := []vexRawDocument{
		{Path: filepath.Join(root, ".vulnetix", "x.openvex.json"), Data: []byte(testOpenVEX)},
		{Path: filepath.Join(root, "dup.json"), Data: []byte(testOpenVEX)}, // same bytes: sent once
		{Path: filepath.Join(root, "notes.json"), Data: []byte(`{"hello":"world"}`)},
		{Path: "/elsewhere/vendor.cdx.json", Data: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)},
		{Path: "big.openvex.json", Data: bytes.Repeat([]byte(" "), vdb.VexIngestMaxDocumentBytes+1)},
	}
	reqs, notes := buildVEXIngestRequests(vexIngestInput{
		Origin: vdb.VexOriginScanVexFile, Docs: docs, Git: git, SnapshotUuid: "snap-1",
	})
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Origin != "scan_vex_file" || r.RepositoryFullName != "acme/widget" || r.GitCommit != "abc123" || r.IngestionSnapshotUuid != "snap-1" {
		t.Fatalf("request context = %+v", r)
	}
	if len(r.Documents) != 2 {
		t.Fatalf("documents = %+v, want the OpenVEX and the CycloneDX", r.Documents)
	}
	first := r.Documents[0]
	if first.Path != ".vulnetix/x.openvex.json" || first.Format != "openvex" {
		t.Errorf("first doc = %+v", first)
	}
	sum := sha256.Sum256([]byte(testOpenVEX))
	if first.Sha256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %s", first.Sha256)
	}
	if raw, _ := base64.StdEncoding.DecodeString(first.Content); string(raw) != testOpenVEX {
		t.Errorf("content does not round-trip")
	}
	if second := r.Documents[1]; second.Path != "vendor.cdx.json" || second.Format != "cyclonedx" {
		t.Errorf("a file outside the repo is sent by base name only: %+v", second)
	}
	if len(notes) != 2 {
		t.Errorf("notes = %v, want one for the non-VEX file and one for the oversized one", notes)
	}
}

func TestBuildVEXIngestRequestsChunks(t *testing.T) {
	var docs []vexRawDocument
	for i := 0; i < 23; i++ {
		docs = append(docs, vexRawDocument{Path: "d.json", Data: []byte(strings.Replace(testOpenVEX, "urn:x", "urn:"+string(rune('a'+i)), 1))})
	}
	reqs, _ := buildVEXIngestRequests(vexIngestInput{Origin: vdb.VexOriginUpload, Docs: docs})
	if len(reqs) != 3 || len(reqs[0].Documents) != 10 || len(reqs[2].Documents) != 3 {
		t.Fatalf("chunks = %d (%d, ..., %d)", len(reqs), len(reqs[0].Documents), len(reqs[len(reqs)-1].Documents))
	}
}

func TestIngestVEXOfflineSendsNothing(t *testing.T) {
	prev := vexIngestAllowed
	vexIngestAllowed = func() bool { return false }
	t.Cleanup(func() { vexIngestAllowed = prev })

	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	t.Setenv("VULNETIX_API_URL", srv.URL)

	if got := ingestVEX(context.Background(), vexIngestInput{
		Origin: vdb.VexOriginScanVexFile, Docs: []vexRawDocument{{Path: "a.json", Data: []byte(testOpenVEX)}}, Warn: io.Discard,
	}); got != nil || hit {
		t.Fatalf("an unauthenticated run sent VEX (results %v, hit %v)", got, hit)
	}
}

func TestIngestVEXPostsAndNeverFails(t *testing.T) {
	prev := vexIngestAllowed
	vexIngestAllowed = func() bool { return true }
	t.Cleanup(func() { vexIngestAllowed = prev })

	var got vdb.CliVexIngestRequest
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The community credential exchanges for a token first.
		if r.URL.Path == "/v2/auth/token" {
			_, _ = w.Write([]byte(`{"token":"t","exp":4102444800}`))
			return
		}
		if r.URL.Path != "/v2/cli.vex-ingest" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if fail {
			http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
			return
		}
		var env struct {
			Payload vdb.CliVexIngestRequest `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&env)
		got = env.Payload
		_, _ = w.Write([]byte(`{"meta":{},"data":{"documents":[{"path":"a.json","statements":1,"created":["u1"],"applied":1}]}}`))
	}))
	defer srv.Close()
	t.Setenv("VULNETIX_API_URL", srv.URL)

	var warn bytes.Buffer
	res := ingestVEX(context.Background(), vexIngestInput{
		Origin: vdb.VexOriginBOMEnrich, Docs: []vexRawDocument{{Path: "a.json", Data: []byte(testOpenVEX)}}, Warn: &warn,
	})
	if len(res) != 1 || len(res[0].Created) != 1 {
		t.Fatalf("results = %+v", res)
	}
	if got.Origin != "bom_enrich" || len(got.Documents) != 1 {
		t.Fatalf("payload = %+v", got)
	}

	fail = true
	warn.Reset()
	if res := ingestVEX(context.Background(), vexIngestInput{
		Origin: vdb.VexOriginBOMEnrich, Docs: []vexRawDocument{{Path: "a.json", Data: []byte(testOpenVEX)}}, Warn: &warn,
	}); res != nil {
		t.Fatalf("results on failure = %+v", res)
	}
	if !strings.Contains(warn.String(), "warning: could not send") {
		t.Fatalf("failure not reported as a warning: %q", warn.String())
	}
}

func TestCDXHasAnalysis(t *testing.T) {
	cases := map[string]bool{
		`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1"}]}`:                                     false,
		`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{}}]}`:                       false,
		`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected"}}]}`: true,
		`{"bomFormat":"CycloneDX","components":[]}`:                                                        false,
		`not json`: false,
	}
	for doc, want := range cases {
		if got := cdxHasAnalysis([]byte(doc)); got != want {
			t.Errorf("cdxHasAnalysis(%s) = %v, want %v", doc, got, want)
		}
	}
}

func TestCliIdentity(t *testing.T) {
	git := &gitctx.GitContext{HeadCommitAuthor: "Ada", HeadCommitEmail: "ada@example.com", RepoRootPath: t.TempDir() + "/missing"}
	sys := &gitctx.SystemInfo{Username: "ci", Hostname: "runner-1"}
	ci := &vdb.CliCIContext{Provider: "github-actions", Actor: "octo", TriggeringActor: "cat", Repository: "acme/widget", RunID: 42, SHA: "deadbeef"}

	id := cliIdentity(git, sys, ci)
	if id == nil {
		t.Fatal("identity is nil")
	}
	want := vdb.CliIdentity{
		HeadAuthorName: "Ada", HeadAuthorEmail: "ada@example.com", OSUser: "ci", Hostname: "runner-1",
		CIProvider: "github-actions", CIActor: "octo", CITriggeringActor: "cat", CIRepository: "acme/widget", CIRunID: "42", CISha: "deadbeef",
	}
	// git config is read from a directory that does not exist, so it is empty.
	id.GitConfigName, id.GitConfigEmail = "", ""
	if *id != want {
		t.Fatalf("identity = %+v\nwant       %+v", *id, want)
	}

	b, _ := json.Marshal(vdb.CliEnv{Identity: &want})
	for _, key := range []string{`"identity"`, `"headAuthorEmail"`, `"osUser"`, `"ciTriggeringActor"`, `"ciRunId":"42"`, `"ciSha"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("wire form %s lacks %s", b, key)
		}
	}
}

func TestLocalSuppressionsRecorded(t *testing.T) {
	resetLocalSuppressions()
	t.Cleanup(resetLocalSuppressions)

	set := suppress.NewSet([]suppress.Rule{
		{UUID: "rule-1", FindingID: "CVE-1", IsActive: true, Source: suppress.SourceRemote, Type: "risk_accepted", Reason: "vendor says no"},
		{RuleID: "go-sqli", IsActive: true, Source: suppress.SourceMemory, Category: "sast"},
	}, 0)

	vulns := []scan.EnrichedVuln{
		{VulnFinding: scan.VulnFinding{CveID: "CVE-1", PackageName: "left-pad", PackageVer: "1.0.0", Ecosystem: "npm", SourceFile: "package-lock.json"}},
		{VulnFinding: scan.VulnFinding{CveID: "CVE-2", PackageName: "left-pad", PackageVer: "1.0.0", Ecosystem: "npm"}},
	}
	kept, n := filterSuppressedVulns(vulns, set)
	if n != 1 || len(kept) != 1 {
		t.Fatalf("kept %d dropped %d", len(kept), n)
	}
	// The same finding hidden twice is one entry.
	filterSuppressedVulns([]scan.EnrichedVuln{vulns[0]}, set)

	recordNosecHits(nil, nil, nil)
	got := localSuppressionsForFinalize()
	if len(got) != 1 {
		t.Fatalf("recorded = %+v", got)
	}
	want := vdb.CliLocalSuppression{
		RuleUUID: "rule-1", Source: "remote", Category: "sca", FindingID: "CVE-1",
		Purl: "pkg:npm/left-pad@1.0.0", FilePath: "package-lock.json", Type: "risk_accepted", Reason: "vendor says no",
	}
	if got[0] != want {
		t.Fatalf("recorded %+v\nwant     %+v", got[0], want)
	}

	b, _ := json.Marshal(vdb.CliFinalizeRequest{LocalSuppressions: got})
	for _, key := range []string{`"localSuppressions"`, `"ruleUuid":"rule-1"`, `"source":"remote"`, `"purl"`, `"findingId"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("finalize wire form %s lacks %s", b, key)
		}
	}
}

// A finding hidden by a --vex-file statement is VEX, not a rule application:
// filterVEXSuppressed must not report it as a local suppression.
func TestVEXFilteringIsNotALocalSuppression(t *testing.T) {
	resetLocalSuppressions()
	t.Cleanup(resetLocalSuppressions)

	pass := &VEXPassResult{Result: &vex.Result{
		Suppressed: 1,
		Applied:    []vex.AppliedStatement{{VulnID: "CVE-1", Status: vex.StatusNotAffected, Suppressed: true}},
	}}
	kept := filterVEXSuppressed([]scan.EnrichedVuln{{VulnFinding: scan.VulnFinding{CveID: "CVE-1"}}}, pass)
	if len(kept) != 0 {
		t.Fatalf("VEX did not hide the finding: %+v", kept)
	}
	if got := localSuppressionsForFinalize(); len(got) != 0 {
		t.Fatalf("VEX filtering recorded local suppressions: %+v", got)
	}
}

// Only a real account is named: the embedded community key and a token with
// no org (resolved server-side) leave the decision to the local fallback.
func TestAccountActorFor(t *testing.T) {
	cases := []struct {
		name  string
		creds *auth.Credentials
		want  string
	}{
		{"none", nil, ""},
		{"community", auth.CommunityCredentials(), ""},
		{"token without org", &auth.Credentials{Token: "t", Method: auth.Token}, ""},
		{"device login key", &auth.Credentials{OrgID: "acct-1", APIKey: "k", Method: auth.DirectAPIKey}, "vulnetix:acct-1"},
		{"sigv4", &auth.Credentials{OrgID: "acct-2", Secret: "s", Method: auth.SigV4}, "vulnetix:acct-2"},
	}
	for _, c := range cases {
		if got := accountActorFor(c.creds); got != c.want {
			t.Errorf("%s: accountActorFor = %q, want %q", c.name, got, c.want)
		}
	}
}
