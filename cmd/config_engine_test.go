package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

const testTenant = "11111111-1111-4111-8111-111111111111"

// fakeEngine is an httptest stand-in for vdb-site's /api/site/v1/config/*
// and, for the deprecated aliases, vdb-api's /v2/cli.quality-gate-*.
type fakeEngine struct {
	t   *testing.T
	srv *httptest.Server

	mu     sync.Mutex
	calls  []string // "METHOD path"
	bodies map[string][]map[string]any
	auth   map[string]string
	query  map[string]string
	plan   map[string]any
	status map[string]int // per path, non-200 answers
	// applyCode and applyItems replace the apply answer (207, failed objects).
	applyCode   int
	applyItems  []any
	applyFailed int
	errBody     map[string]any
	exportOK    string
}

func newFakeEngine(t *testing.T) *fakeEngine {
	f := &fakeEngine{t: t, bodies: map[string][]map[string]any{}, auth: map[string]string{},
		query: map[string]string{}, status: map[string]int{}}
	f.plan = map[string]any{
		"tenant": testTenant, "manager": "gitops:acme/platform", "prune": false,
		"items": []any{map[string]any{"kind": "QualityGate", "name": "default", "action": "update",
			"changes": []any{map[string]any{"path": "severity", "from": "low", "to": "high"}}}},
		"blocking": []any{}, "warnings": []any{},
		"summary":  map[string]any{"create": 0, "update": 1, "delete": 0, "noop": 0},
		"planHash": "hash-1",
	}
	f.exportOK = "apiVersion: vulnetix.com/v1\nkind: QualityGate\n"
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	t.Setenv("VULNETIX_WEB_URL", f.srv.URL)
	t.Setenv(configTokenEnv, "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "abc123")
	return f
}

func (f *fakeEngine) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/site/v1")
	f.calls = append(f.calls, r.Method+" "+path)
	f.auth[path] = r.Header.Get("Authorization")
	f.query[path] = r.URL.RawQuery
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.bodies[path] = append(f.bodies[path], m)
	}
	if st := f.status[path]; st != 0 {
		w.WriteHeader(st)
		_ = json.NewEncoder(w).Encode(f.errBody)
		return
	}
	switch path {
	case "/config/plan":
		_ = json.NewEncoder(w).Encode(f.plan)
	case "/config/apply":
		if f.applyItems != nil {
			if f.applyCode != 0 {
				w.WriteHeader(f.applyCode)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"planHash": f.plan["planHash"], "summary": f.plan["summary"], "failed": f.applyFailed, "items": f.applyItems})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"planHash": f.plan["planHash"], "summary": f.plan["summary"],
			"items": []any{map[string]any{"kind": "QualityGate", "name": "default", "action": "update",
				"status": map[string]any{"phase": "Applied"}}}})
	case "/config/export":
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = io.WriteString(w, f.exportOK)
	case "/v2/cli.quality-gate-config", "/v2/cli.quality-gate-get":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"config": map[string]any{"severity": "high"}}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeEngine) called(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

func (f *fakeEngine) lastBody(path string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	bs := f.bodies[path]
	if len(bs) == 0 {
		f.t.Fatalf("no request to %s", path)
	}
	return bs[len(bs)-1]
}

func runCmd(t *testing.T, cmd *cobra.Command, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func gateFile(t *testing.T, body string) string {
	if body == "" {
		body = validGate
	}
	return writeConfigFile(t, t.TempDir(), "gate.yaml", body)
}

func TestConfigPlanRendersTheEnginePlan(t *testing.T) {
	f := newFakeEngine(t)
	out, _, err := runCmd(t, newConfigPlanCommand(), "", "-f", gateFile(t, ""), "--manager", "gitops:acme/platform", "--token", "vmt_abc")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"~ QualityGate/default  update", `severity: "low" -> "high"`, "0 to create, 1 to update", "Plan hash: hash-1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if got := f.auth["/config/plan"]; got != "Bearer vmt_abc" {
		t.Fatalf("Authorization %q", got)
	}
	body := f.lastBody("/config/plan")
	if body["manager"] != "gitops:acme/platform" || body["sourceRef"] != "abc123" {
		t.Fatalf("body %v", body)
	}
	docs, _ := body["documents"].([]any)
	if len(docs) != 1 {
		t.Fatalf("documents %v", body["documents"])
	}
}

func TestConfigPlanTokenFromEnvironment(t *testing.T) {
	f := newFakeEngine(t)
	t.Setenv(configTokenEnv, "vmt_env")
	if _, _, err := runCmd(t, newConfigPlanCommand(), "", "-f", gateFile(t, ""), "--manager", "terraform"); err != nil {
		t.Fatal(err)
	}
	if got := f.auth["/config/plan"]; got != "Bearer vmt_env" {
		t.Fatalf("Authorization %q", got)
	}
}

func TestConfigPlanJSON(t *testing.T) {
	newFakeEngine(t)
	out, _, err := runCmd(t, newConfigPlanCommand(), "", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var p configPlan
	if err := json.Unmarshal([]byte(out), &p); err != nil || p.PlanHash != "hash-1" {
		t.Fatalf("not the plan JSON (%v):\n%s", err, out)
	}
}

func TestConfigPlanBlockingExitsThree(t *testing.T) {
	f := newFakeEngine(t)
	f.plan["blocking"] = []any{map[string]any{"code": "managed_by_other", "kind": "QualityGate", "name": "default",
		"message": "managed by terraform; only that manager can change it"}}
	out, _, err := runCmd(t, newConfigPlanCommand(), "", "-f", gateFile(t, ""), "--manager", "gitops:acme/platform", "--token", "t")
	if err == nil {
		t.Fatal("want an error")
	}
	if ExitCode(err) != ExitPlanBlocked || ExitPlanBlocked != 3 {
		t.Fatalf("exit %d", ExitCode(err))
	}
	if !strings.Contains(out, "[managed_by_other] QualityGate/default") {
		t.Fatalf("blocking not shown:\n%s", out)
	}
}

func TestConfigPlanRefusesInvalidDocumentsLocally(t *testing.T) {
	f := newFakeEngine(t)
	p := gateFile(t, "apiVersion: vulnetix.com/v1\nkind: QualityGate\nmetadata: {name: default}\nspec: {severity: urgent}\n")
	_, stderr, err := runCmd(t, newConfigPlanCommand(), "", "-f", p, "--manager", "terraform", "--token", "t")
	if err == nil || !strings.Contains(stderr, "/spec/severity") {
		t.Fatalf("err %v stderr %q", err, stderr)
	}
	if f.called("POST /config/plan") != 0 {
		t.Fatal("an invalid document reached the engine")
	}
}

func TestConfigPlanRequiresManagerOutsideAGitHubRepo(t *testing.T) {
	newFakeEngine(t)
	gate := gateFile(t, "")
	t.Chdir(t.TempDir())
	_, _, err := runCmd(t, newConfigPlanCommand(), "", "-f", gate, "--token", "t")
	if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "--manager is required") {
		t.Fatalf("err %v", err)
	}
}

func TestConfigManagerDefaultsToTheGitHubRepo(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "Acme/Platform")
	m, err := detectConfigManager("", t.TempDir())
	if err != nil || m != "gitops:acme/platform" {
		t.Fatalf("%q %v", m, err)
	}
	for in, want := range map[string]string{
		"git@github.com:Acme/platform.git":       "Acme/platform",
		"https://github.com/acme/platform":       "acme/platform",
		"https://x@github.com/acme/platform.git": "acme/platform",
		"ssh://git@github.com/acme/platform.git": "acme/platform",
		"https://gitlab.com/acme/platform":       "",
		"https://github.com/acme":                "",
	} {
		if got := githubRepoFromRemote(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestConfigApplyAutoApproveSendsThePlanHash(t *testing.T) {
	f := newFakeEngine(t)
	out, _, err := runCmd(t, newConfigApplyCommand(), "", "-f", gateFile(t, ""), "--manager", "gitops:acme/platform", "--token", "t", "--auto-approve")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := f.lastBody("/config/apply")["planHash"]; got != "hash-1" {
		t.Fatalf("planHash %v", got)
	}
	if !strings.Contains(out, "QualityGate/default  Applied") {
		t.Fatalf("result not shown:\n%s", out)
	}
}

func TestConfigApplyAsksOnATerminal(t *testing.T) {
	f := newFakeEngine(t)
	old := configStdinIsTerminal
	t.Cleanup(func() { configStdinIsTerminal = old })

	configStdinIsTerminal = func() bool { return false }
	_, _, err := runCmd(t, newConfigApplyCommand(), "", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t")
	if ExitCode(err) != ExitUsage || f.called("POST /config/apply") != 0 {
		t.Fatalf("without a terminal: %v", err)
	}

	configStdinIsTerminal = func() bool { return true }
	_, _, err = runCmd(t, newConfigApplyCommand(), "no\n", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t")
	if err == nil || f.called("POST /config/apply") != 0 {
		t.Fatalf("declined: %v", err)
	}
	_, _, err = runCmd(t, newConfigApplyCommand(), "yes\n", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t")
	if err != nil || f.called("POST /config/apply") != 1 {
		t.Fatalf("approved: %v", err)
	}
}

func TestConfigApplyStateChanged409(t *testing.T) {
	f := newFakeEngine(t)
	f.status["/config/apply"] = http.StatusConflict
	f.errBody = map[string]any{"error": "plan_changed", "message": "the plan changed since it was reviewed; plan again",
		"plan": map[string]any{"summary": map[string]any{"create": 0, "update": 2, "delete": 0, "noop": 0}}}
	_, _, err := runCmd(t, newConfigApplyCommand(), "", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t", "--auto-approve")
	if err == nil || !strings.Contains(err.Error(), "changed after this plan was made") || !strings.Contains(err.Error(), "2 to update") {
		t.Fatalf("err %v", err)
	}
	if ExitCode(err) != ExitFailure {
		t.Fatalf("exit %d", ExitCode(err))
	}
}

func TestConfigApplyBlockedPlanIsNotApplied(t *testing.T) {
	f := newFakeEngine(t)
	f.plan["blocking"] = []any{map[string]any{"code": "invalid", "message": "document 1: bad"}}
	_, _, err := runCmd(t, newConfigApplyCommand(), "", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t", "--auto-approve")
	if ExitCode(err) != ExitPlanBlocked || f.called("POST /config/apply") != 0 {
		t.Fatalf("err %v", err)
	}
}

func TestConfigApplyPlanHashMismatch(t *testing.T) {
	f := newFakeEngine(t)
	_, _, err := runCmd(t, newConfigApplyCommand(), "", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t", "--plan-hash", "hash-0")
	if err == nil || f.called("POST /config/apply") != 0 {
		t.Fatalf("err %v", err)
	}
	if _, _, err := runCmd(t, newConfigApplyCommand(), "", "-f", gateFile(t, ""), "--manager", "terraform", "--token", "t", "--plan-hash", "hash-1"); err != nil {
		t.Fatal(err)
	}
	if f.called("POST /config/apply") != 1 {
		t.Fatal("a matching --plan-hash should apply without asking")
	}
}

func TestConfigApplyRefusesAnotherTenantsDocument(t *testing.T) {
	f := newFakeEngine(t)
	other := "22222222-2222-4222-8222-222222222222"
	p := gateFile(t, "apiVersion: vulnetix.com/v1\nkind: QualityGate\nmetadata: {name: default, org: "+other+"}\nspec: {severity: high}\n")
	_, _, err := runCmd(t, newConfigApplyCommand(), "", "-f", p, "--manager", "terraform", "--token", "t", "--auto-approve")
	if err == nil || !strings.Contains(err.Error(), "metadata.org "+other) || f.called("POST /config/apply") != 0 {
		t.Fatalf("err %v", err)
	}
}

func TestConfigExport(t *testing.T) {
	f := newFakeEngine(t)
	out, _, err := runCmd(t, newConfigExportCommand(), "", "--kind", "QualityGate", "--format", "hcl", "--token", "t")
	if err != nil || out != f.exportOK {
		t.Fatalf("%v %q", err, out)
	}
	if q := f.query["/config/export"]; !strings.Contains(q, "format=hcl") || !strings.Contains(q, "kind=QualityGate") {
		t.Fatalf("query %q", q)
	}

	dst := filepath.Join(t.TempDir(), "out", "gate.yaml")
	if _, _, err := runCmd(t, newConfigExportCommand(), "", "-o", dst, "--token", "t"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != f.exportOK {
		t.Fatalf("file %q", b)
	}

	if _, _, err := runCmd(t, newConfigExportCommand(), "", "-f", gateFile(t, ""), "--format", "sh", "--token", "t"); err != nil {
		t.Fatal(err)
	}
	if f.called("POST /config/export") != 1 || len(f.lastBody("/config/export")["documents"].([]any)) != 1 {
		t.Fatal("a draft export should POST the documents")
	}
}

func TestResolveValueFrom(t *testing.T) {
	t.Setenv("VX_TEST_SECRET", "s3cr3t-env")
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("s3cr3t-file\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := map[string]any{
		"spec": map[string]any{
			"token": map[string]any{"valueFrom": map[string]any{"env": "VX_TEST_SECRET"}},
			"list":  []any{map[string]any{"key": map[string]any{"valueFrom": map[string]any{"file": file}}}},
			"plain": "x",
		},
	}
	out, secrets, err := resolveValueFrom(in, "")
	if err != nil {
		t.Fatal(err)
	}
	spec := out.(map[string]any)["spec"].(map[string]any)
	if spec["token"] != "s3cr3t-env" || spec["list"].([]any)[0].(map[string]any)["key"] != "s3cr3t-file" || spec["plain"] != "x" {
		t.Fatalf("resolved %v", spec)
	}
	if len(secrets) != 2 {
		t.Fatalf("secrets %v", secrets)
	}
	ci := &configInput{secrets: secrets}
	if got := ci.mask(`{"to":"s3cr3t-env"}`); strings.Contains(got, "s3cr3t") {
		t.Fatalf("not masked: %s", got)
	}

	_, _, err = resolveValueFrom(map[string]any{"spec": map[string]any{"k": map[string]any{"valueFrom": map[string]any{"env": "VX_TEST_UNSET_SECRET"}}}}, "")
	if err == nil || !strings.Contains(err.Error(), "spec.k: valueFrom.env: VX_TEST_UNSET_SECRET is not set") {
		t.Fatalf("err %v", err)
	}
}

func TestQualityGateAliasUsesTheEngine(t *testing.T) {
	f := newFakeEngine(t)
	t.Setenv(configTokenEnv, "vmt_alias")
	t.Setenv("VULNETIX_API_TOKEN", "legacy")
	f.plan["manager"] = "console"
	_, stderr, err := runCmd(t, newConfigSetQualityGateCommand(), "", "--severity", "high", "--cooldown", "3", "--base-url", f.srv.URL, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "Deprecated:") || !strings.Contains(stderr, "vulnetix config apply") {
		t.Fatalf("no deprecation notice: %q", stderr)
	}
	body := f.lastBody("/config/plan")
	doc := body["documents"].([]any)[0].(map[string]any)
	spec := doc["spec"].(map[string]any)
	if body["manager"] != "console" || doc["kind"] != "QualityGate" || spec["severity"] != "high" || spec["cooldownDays"] != float64(3) {
		t.Fatalf("plan body %v", body)
	}
	if f.called("POST /config/apply") != 1 || f.called("POST /v2/cli.quality-gate-config") != 0 {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestQualityGateAliasFallsBackWhenTheEngineRefuses(t *testing.T) {
	f := newFakeEngine(t)
	t.Setenv("VULNETIX_API_TOKEN", "legacy")
	f.status["/config/plan"] = http.StatusForbidden
	f.errBody = map[string]any{"error": "only an owner or admin can plan, apply or export configuration"}
	_, stderr, err := runCmd(t, newConfigSetEolPolicyCommand(), "", "--retired-severity", "critical", "--base-url", f.srv.URL, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "Using the legacy quality-gate endpoint") || !strings.Contains(stderr, "HTTP 403") {
		t.Fatalf("fallback not explained: %q", stderr)
	}
	if f.called("POST /v2/cli.quality-gate-config") != 1 {
		t.Fatalf("legacy path not taken: %v", f.calls)
	}
}

func TestQualityGateAliasUnsetGoesStraightToLegacy(t *testing.T) {
	f := newFakeEngine(t)
	t.Setenv("VULNETIX_API_TOKEN", "legacy")
	_, stderr, err := runCmd(t, newConfigSetQualityGateCommand(), "", "--severity", "null", "--base-url", f.srv.URL, "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if f.called("POST /config/plan") != 0 || f.called("POST /v2/cli.quality-gate-config") != 1 || !strings.Contains(stderr, "cannot unset") {
		t.Fatalf("calls %v stderr %q", f.calls, stderr)
	}
}
