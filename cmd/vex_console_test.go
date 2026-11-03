package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/internal/cdx"
	"github.com/vulnetix/cli/v4/pkg/auth"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// The rules a console VexSource made, as cli.suppressions-get returns them.
const consoleRulesReply = `{"meta":{},"data":{"vexTruncated":false,"suppressions":[
 {"uuid":"cli-1","ruleId":"CVE-2020-1","category":"sca","suppressionType":"risk_accepted","isActive":true,"sourceKind":"cli_ignore"},
 {"uuid":"vex-tea","suppressionType":"false_positive","reason":"vendor says so","isActive":true,"sourceKind":"vex","vexSourceUuid":"vs-1",
  "source":"vendor-tea","sourceType":"tea","sourceRef":"stmt-1","sourceDocumentId":"doc-1","statementTimestamp":1700000000,
  "vulnerabilityId":"CVE-2020-8203","productPurl":"pkg:npm/lodash@4.17.20","justification":"vulnerable_code_not_present","status":"not_affected"},
 {"uuid":"vex-git","suppressionType":"wont_fix","reason":"accepted","isActive":true,"sourceKind":"vex","vexSourceUuid":"vs-2",
  "source":"team-git","sourceType":"git","vulnerabilityId":"CVE-2024-9999","productPurl":"pkg:npm/express@4.18.2","status":"affected"},
 {"uuid":"vex-other-repo","suppressionType":"false_positive","isActive":true,"sourceKind":"vex","vexSourceUuid":"vs-2","source":"team-git","sourceType":"git",
  "repositoryFullName":"acme/other","vulnerabilityId":"CVE-2021-1111","productPurl":"pkg:npm/left-pad@1.3.0","status":"not_affected"},
 {"uuid":"vex-ingested","suppressionType":"false_positive","isActive":true,"sourceKind":"vex","vulnerabilityId":"CVE-2099-1","productPurl":"pkg:npm/x@1","status":"not_affected"}
]}}`

// consoleServer answers cli.suppressions-get and records the deactivations it is sent.
type consoleServer struct {
	*httptest.Server
	gets, sets atomic.Int32
	mu         sync.Mutex
	deact      []vdb.CliSuppressionSetRequest
}

func newConsoleServer(t *testing.T, reply string) *consoleServer {
	t.Helper()
	cs := &consoleServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/auth/token":
			_, _ = w.Write([]byte(`{"token":"t","exp":4102444800}`))
		case "/v2/cli.suppressions-get":
			cs.gets.Add(1)
			_, _ = w.Write([]byte(reply))
		case "/v2/cli.suppressions":
			cs.sets.Add(1)
			var env struct {
				Payload vdb.CliSuppressionSetRequest `json:"payload"`
			}
			_ = json.NewDecoder(r.Body).Decode(&env)
			cs.mu.Lock()
			cs.deact = append(cs.deact, env.Payload)
			cs.mu.Unlock()
			_, _ = w.Write([]byte(`{"meta":{},"data":{"deactivated":1}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cs.Close)
	t.Setenv("VULNETIX_API_URL", cs.URL)
	return cs
}

func resetRemoteSuppressions(t *testing.T) {
	t.Helper()
	remoteSuppressionsMu.Lock()
	remoteSuppressions = map[string]*future[remoteSuppressionData]{}
	remoteSuppressionsMu.Unlock()
	t.Cleanup(func() {
		remoteSuppressionsMu.Lock()
		remoteSuppressions = map[string]*future[remoteSuppressionData]{}
		remoteSuppressionsMu.Unlock()
	})
}

func asOrg(t *testing.T) {
	t.Helper()
	orig := vdbCreds
	vdbCreds = &auth.Credentials{OrgID: "real-org", APIKey: "real-key", Method: auth.DirectAPIKey}
	t.Cleanup(func() { vdbCreds = orig })
}

func consoleRows(t *testing.T) []vdb.CliSuppression {
	t.Helper()
	var r struct {
		Data vdb.CliSuppressionsListData `json:"data"`
	}
	if err := json.Unmarshal([]byte(consoleRulesReply), &r); err != nil {
		t.Fatal(err)
	}
	return r.Data.Suppressions
}

// A VEX-sourced rule is a statement, not an ignore rule: it goes to the VEX
// pass and never into the matcher internal/suppress runs.
func TestFetchRemoteSuppressionsSplitsVEXFromIgnoreRules(t *testing.T) {
	resetRemoteSuppressions(t)
	asOrg(t)
	newConsoleServer(t, consoleRulesReply)
	data := fetchRemoteSuppressions(newCliClient(), nil, vdb.CliSuppressionsGetRequest{ActiveOnly: true})
	if len(data.Rules) != 1 || data.Rules[0].UUID != "cli-1" {
		t.Errorf("ignore rules = %+v", data.Rules)
	}
	if len(data.VEX) != 4 || data.VEXTruncated {
		t.Errorf("VEX rows = %d truncated %v", len(data.VEX), data.VEXTruncated)
	}
	if v := data.VEX[0]; v.Source != "vendor-tea" || v.SourceType != "tea" || v.Status != "not_affected" || v.ProductPurl != "pkg:npm/lodash@4.17.20" ||
		v.Justification != "vulnerable_code_not_present" || v.StatementTimestamp != 1700000000 || v.VexSourceUUID != "vs-1" {
		t.Errorf("first VEX row = %+v", v)
	}
}

func TestConsoleVEXRulesScope(t *testing.T) {
	rows := consoleRows(t)
	// In acme/app on main the other repository's rule and the ordinary rule are out.
	got := consoleVEXRules(rows, "acme/app", "main")
	var ids []string
	for _, r := range got {
		ids = append(ids, r.VulnerabilityID)
	}
	if strings.Join(ids, ",") != "CVE-2020-8203,CVE-2024-9999,CVE-2099-1" {
		t.Errorf("rules in acme/app = %v", ids)
	}
	// A scan that does not know its repository applies only what is not scoped to one.
	got = consoleVEXRules(rows, "", "")
	if len(got) != 3 {
		t.Errorf("rules with no repository = %d, want the 3 unscoped ones", len(got))
	}
	rows[1].BranchName = "release"
	if got := consoleVEXRules(rows, "acme/app", "main"); len(got) != 2 {
		t.Errorf("a branch-scoped rule applied on another branch: %d rules", len(got))
	}
	rows[2].IsActive = false
	if got := consoleVEXRules(rows, "acme/app", "release"); len(got) != 2 {
		t.Errorf("an inactive rule applied: %d rules", len(got))
	}
}

func TestScanConsoleVEXNeedsAuthenticationAndVEXOn(t *testing.T) {
	// Community mode asks for nothing and applies nothing.
	resetRemoteSuppressions(t)
	cs := newConsoleServer(t, consoleRulesReply)
	orig := vdbCreds
	vdbCreds = auth.CommunityCredentials()
	t.Cleanup(func() { vdbCreds = orig })
	if got := scanConsoleVEX(true, nil, nil); got != nil || cs.gets.Load() != 0 {
		t.Fatalf("community: %d rules, %d requests", len(got), cs.gets.Load())
	}

	// --no-vex (enabled false) applies nothing, authenticated or not.
	asOrg(t)
	if got := scanConsoleVEX(false, nil, nil); got != nil || cs.gets.Load() != 0 {
		t.Fatalf("--no-vex: %d rules, %d requests", len(got), cs.gets.Load())
	}

	// Authenticated: the console's statements, with a note when the list was cut.
	if got := scanConsoleVEX(true, nil, nil); len(got) != 3 {
		t.Fatalf("authenticated: %d rules", len(got))
	}
	resetRemoteSuppressions(t)
	cs.Close()
	truncated := newConsoleServer(t, strings.Replace(consoleRulesReply, `"vexTruncated":false`, `"vexTruncated":true`, 1))
	_ = truncated
	var notes bytes.Buffer
	scanConsoleVEX(true, nil, &notes)
	if !strings.Contains(notes.String(), "more VEX statements") {
		t.Errorf("no note for a truncated reply: %q", notes.String())
	}
}

// The scan's one VEX pass: the console's statements close the finding they are
// about, the ones a --vex document already makes are not applied twice, and the
// counts tell the two apart.
func TestRunVEXPassAppliesConsoleStatements(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "vendor.openvex.json")
	if err := os.WriteFile(local, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:local","author":"me","timestamp":"2025-01-01T00:00:00Z","version":1,
	  "statements":[{"vulnerability":{"name":"CVE-2020-8203"},"products":[{"@id":"pkg:npm/lodash@4.17.20"}],"status":"not_affected","justification":"vulnerable_code_not_present"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Components: []cdx.Component{
			{Type: "library", BOMRef: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"},
			{Type: "library", BOMRef: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Purl: "pkg:npm/express@4.18.2"},
			{Type: "library", BOMRef: "pkg:npm/left-pad@1.3.0", Name: "left-pad", Version: "1.3.0", Purl: "pkg:npm/left-pad@1.3.0"},
		},
		Vulnerabilities: []cdx.Vulnerability{
			{ID: "CVE-2020-8203", Affects: []cdx.Affect{{Ref: "pkg:npm/lodash@4.17.20"}}},
			{ID: "CVE-2024-9999", Affects: []cdx.Affect{{Ref: "pkg:npm/express@4.18.2"}}},
			{ID: "CVE-2021-1111", Affects: []cdx.Affect{{Ref: "pkg:npm/left-pad@1.3.0"}}},
		}}

	// Console only: the tea statement closes lodash, the git one (a decision
	// not to fix) annotates express without closing it, the other repository's
	// closes nothing here.
	rules := consoleVEXRules(consoleRows(t), "acme/app", "main")
	pass, err := runVEXPass(VEXPassOptions{BOM: bom, Console: rules})
	if err != nil {
		t.Fatal(err)
	}
	if pass.Result.Suppressed != 1 || pass.Result.Annotated != 1 || pass.Result.Effective != 2 {
		t.Fatalf("console only: suppressed %d annotated %d effective %d", pass.Result.Suppressed, pass.Result.Annotated, pass.Result.Effective)
	}
	if pass.ConsoleStatements != 3 || pass.ConsoleDuplicates != 0 || pass.Documents != 0 || len(pass.Raw) != 0 {
		t.Errorf("console only: %+v", pass)
	}
	var out bytes.Buffer
	captureReport := captureStderr(t, func() { reportVEXPass(pass) })
	out.WriteString(captureReport)
	if !strings.Contains(out.String(), "from Vulnetix") || !strings.Contains(out.String(), "Vulnetix VexSource/vendor-tea") {
		t.Errorf("report does not say where the statements came from:\n%s", out.String())
	}

	// With the same statement in a --vex document, the console's copy is not applied again.
	bom2 := *bom
	bom2.Vulnerabilities = append([]cdx.Vulnerability(nil), bom.Vulnerabilities...)
	for i := range bom2.Vulnerabilities {
		bom2.Vulnerabilities[i].Analysis = nil
		bom2.Vulnerabilities[i].Properties = nil
	}
	pass, err = runVEXPass(VEXPassOptions{Paths: []string{local}, BOM: &bom2, Console: rules})
	if err != nil {
		t.Fatal(err)
	}
	if pass.ConsoleDuplicates != 1 || pass.ConsoleStatements != 2 || pass.Documents != 1 || pass.Statements != 3 {
		t.Errorf("with a document: duplicates %d console %d documents %d statements %d, want 1, 2, 1, 3",
			pass.ConsoleDuplicates, pass.ConsoleStatements, pass.Documents, pass.Statements)
	}
	if pass.Result.Suppressed != 1 || len(pass.Raw) != 1 {
		t.Errorf("with a document: suppressed %d, raw %d (only the document is sent to Vulnetix)", pass.Result.Suppressed, len(pass.Raw))
	}
	for _, a := range pass.Result.Applied {
		if a.VulnID == "CVE-2020-8203" && !strings.HasSuffix(a.Source, "vendor.openvex.json") {
			t.Errorf("the document, not the console copy, is the source of the shared statement: %q", a.Source)
		}
	}
}

func newRemoveCmd(t *testing.T, path string, flags map[string]string) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "remove"}
	c.Flags().String("path", path, "")
	for _, f := range []string{"uuid", "rule", "finding", "value", "reason"} {
		c.Flags().String(f, "", "")
	}
	for k, v := range flags {
		if err := c.Flags().Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// `ignore remove` does not take away a rule a VexSource owns, and says where to
// change it. Nothing is deactivated, remotely or locally.
func TestIgnoreRemoveRefusesAVexSourceRule(t *testing.T) {
	asOrg(t)
	cs := newConsoleServer(t, consoleRulesReply)
	dir := t.TempDir()

	err := runSuppressRemove(newRemoveCmd(t, dir, map[string]string{"uuid": "vex-tea"}), nil)
	if err == nil {
		t.Fatal("removing a VexSource's rule succeeded")
	}
	for _, want := range []string{"VexSource/vendor-tea", "tea", "CVE-2020-8203", "at the source"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if cs.sets.Load() != 0 {
		t.Errorf("%d deactivations sent to the server", cs.sets.Load())
	}

	// An ordinary rule is still removable.
	if err := runSuppressRemove(newRemoveCmd(t, dir, map[string]string{"uuid": "cli-1"}), nil); err != nil {
		t.Fatal(err)
	}
	if cs.sets.Load() != 1 || cs.deact[0].UUID != "cli-1" {
		t.Errorf("deactivations = %+v", cs.deact)
	}
}

// A memory.yaml an older CLI filled with every remote rule can hold a copy of a
// VexSource's rule. Removing it by the anchor it shares with an ordinary rule
// takes the copy and the ordinary rule away, never the source's rule.
func TestIgnoreRemoveLeavesTheSourceRuleBehindALocalCopy(t *testing.T) {
	asOrg(t)
	cs := newConsoleServer(t, consoleRulesReply)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".vulnetix"), 0o755); err != nil {
		t.Fatal(err)
	}
	mem := "suppressions:\n" +
		"  - uuid: vex-tea\n    finding_id: CVE-2020-8203\n    type: false_positive\n    is_active: true\n" +
		"  - uuid: cli-1\n    finding_id: CVE-2020-8203\n    type: risk_accepted\n    is_active: true\n"
	if err := os.WriteFile(filepath.Join(dir, ".vulnetix", "memory.yaml"), []byte(mem), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSuppressRemove(newRemoveCmd(t, dir, map[string]string{"finding": "CVE-2020-8203"}), nil); err != nil {
		t.Fatal(err)
	}
	for _, d := range cs.deact {
		if d.UUID == "vex-tea" {
			t.Errorf("the source's rule was deactivated: %+v", cs.deact)
		}
	}
	if cs.sets.Load() != 1 || cs.deact[0].UUID != "cli-1" {
		t.Errorf("deactivations = %+v", cs.deact)
	}
}

func TestIgnoreSyncLeavesVexSourceRulesWhereTheyAre(t *testing.T) {
	asOrg(t)
	newConsoleServer(t, consoleRulesReply)
	dir := t.TempDir()
	c := &cobra.Command{Use: "sync"}
	c.Flags().String("path", dir, "")
	out := captureStdout(t, func() {
		if err := runSuppressSync(c, nil); err != nil {
			t.Fatal(err)
		}
	})
	data, err := os.ReadFile(filepath.Join(dir, ".vulnetix", "memory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "cli-1") || strings.Contains(string(data), "vex-tea") || strings.Contains(string(data), "vex-git") {
		t.Errorf("memory.yaml after sync:\n%s", data)
	}
	if !strings.Contains(out, "owned by a VexSource") {
		t.Errorf("sync output = %q", out)
	}
}

func TestVexOwnedErrorNamesTheSource(t *testing.T) {
	err := vexOwnedError(vdb.CliSuppression{VulnerabilityID: "CVE-1", ProductPurl: "pkg:npm/a@1", Source: "s3-feed", SourceType: "s3"})
	if !strings.Contains(err.Error(), "CVE-1 for pkg:npm/a@1") || !strings.Contains(err.Error(), "VexSource/s3-feed (s3)") {
		t.Error(err)
	}
}
