//go:build linux && (amd64 || arm64)

package agent

import (
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/execguard"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/host"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

func TestMain(m *testing.M) {
	execguard.MaybeChild()
	os.Exit(m.Run())
}

// A real workload under the real seccomp guard: a block-mode Sigma rule on a
// signed feed refuses the exec in enforce, the workload sees EPERM (126 from
// sh), and the event says blocked.
func TestExecGuardRefusesAMatchingExec(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false")
	}
	out := filepath.Join(t.TempDir(), "status")

	pub, priv, _ := ed25519.GenerateKey(nil)
	p := &platform{}
	publish(t, p, priv, []feed.Rule{{
		RuleTable: "countermeasure", RuleUUID: "cm-1", RuleType: "SIGMA", DeployMode: "block",
		Body: "title: no false\nlogsource: {category: process_creation}\ndetection: {sel: {Image|endswith: /false}, condition: sel}\n",
	}})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	a := New(Config{
		SensorKey: "k", Version: "test", Mode: decide.Enforce, Facts: host.Facts{ComputeKind: "ecs", Hostname: "h"},
		Feeds:     []*feed.Source{{BaseURL: srv.URL + "/feed", PublicKey: pub}},
		Uplink:    &uplink.Client{Endpoint: srv.URL, Creds: &auth.Credentials{Method: auth.SigV4, OrgID: "o", Secret: "s"}},
		ExecGuard: []string{sh, "-c", falsePath + "; echo $? > " + out + "; exit 5"},
		Logf:      t.Logf,
	})
	if err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.ExitCode != 5 {
		t.Fatalf("exit code = %d, want 5", a.ExitCode)
	}
	status, _ := os.ReadFile(out)
	if strings.TrimSpace(string(status)) != "126" {
		t.Fatalf("the refused exec returned %q, want 126", status)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.events) != 1 || p.events[0].RuleUUID != "cm-1" || p.events[0].Action != string(decide.Blocked) || p.events[0].Subject != falsePath {
		t.Fatalf("events = %+v", p.events)
	}
	if !strings.Contains(string(p.registers[0]["capabilities"]), `"seccomp":true`) {
		t.Fatalf("capabilities = %s", p.registers[0]["capabilities"])
	}
}
