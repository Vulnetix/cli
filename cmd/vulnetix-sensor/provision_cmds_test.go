package main

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/provision"
)

func parseSensorFlags(t *testing.T, args ...string) (*flag.FlagSet, *options) {
	t.Helper()
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := defineFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}

	return fs, o
}

func TestFlagsOnTheCommandLineWinOverTheProfile(t *testing.T) {
	cfg := provision.Config{
		Mode: "enforce", Hold: "30m", Feeds: []string{"https://profile/feed"},
		EgressListen: "127.0.0.1:3128", DNSListen: "127.0.0.1:53", InventoryEvery: "1h", Forward: []string{"siem"},
	}
	fs, o := parseSensorFlags(t, "--mode", "monitor", "--feed", "https://flag/feed", "--dns-listen", "")
	explicit := explicitFlags(fs)
	if err := applySnapshot(fs, explicit, cfg); err != nil {
		t.Fatal(err)
	}
	if *o.mode != "monitor" || *o.dnsListen != "" || !slices.Equal(o.feeds, multi{"https://flag/feed"}) {
		t.Fatalf("explicit flags were overridden: mode=%s dns=%q feeds=%v", *o.mode, *o.dnsListen, o.feeds)
	}
	if *o.hold != 30*time.Minute || *o.egressListen != "127.0.0.1:3128" || *o.inventoryEvery != time.Hour || !slices.Equal(o.forward, multi{"siem"}) {
		t.Fatalf("profile defaults not applied: hold=%s egress=%q inv=%s fwd=%v", *o.hold, *o.egressListen, *o.inventoryEvery, o.forward)
	}

	// "" in the profile turns a listener off; an empty feed key keeps the pinned one.
	fs, o = parseSensorFlags(t)
	if err := applySnapshot(fs, explicitFlags(fs), provision.Config{EgressListen: ""}); err != nil {
		t.Fatal(err)
	}
	if *o.egressListen != "" || *o.feedKey != defaultFeedKey() || *o.mode != "monitor" {
		t.Fatalf("egress=%q key=%q mode=%s", *o.egressListen, *o.feedKey, *o.mode)
	}
}

func TestDiffConfigSplitsLiveFromRestart(t *testing.T) {
	base := provision.Config{Mode: "monitor", Hold: "15m", Feeds: []string{"a"}, EgressListen: ":3128"}
	live := base
	live.Mode, live.Hold, live.Feeds, live.Protection, live.HeartbeatAlertMinutes = "guard", "5m", []string{"a", "b"}, "hardened", 30
	d := diffConfig(base, live, nil)
	if !d.Mode || !d.Hold || !d.Feeds || d.Restart {
		t.Fatalf("live = %+v", d)
	}
	restart := base
	restart.DNSListen = ":53"
	if d := diffConfig(base, restart, nil); !d.Restart {
		t.Fatal("a new listener needs a restart")
	}
	if d := diffConfig(base, restart, map[string]bool{"dns-listen": true}); d.Restart {
		t.Fatal("a listener fixed on the command line is not the profile's to change")
	}
	if d := diffConfig(base, live, map[string]bool{"mode": true}); d.Mode {
		t.Fatal("a mode fixed on the command line is kept")
	}
}

// fakeSystemctl records calls and answers is-active / is-enabled.
type fakeSystemctl struct {
	calls           [][]string
	active, enabled string
}

func (f *fakeSystemctl) run(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	switch args[0] {
	case "is-active":
		return f.active, nil
	case "is-enabled":
		return f.enabled, nil
	case "start":
		f.active = "active"
	}

	return "", nil
}

func (f *fakeSystemctl) called(args ...string) bool {
	for _, c := range f.calls {
		if slices.Equal(c, args) {
			return true
		}
	}

	return false
}

func withFakeSystem(t *testing.T) (*fakeSystemctl, string) {
	t.Helper()
	root := t.TempDir()
	f := &fakeSystemctl{active: "inactive", enabled: "disabled"}
	oldS, oldR, oldU, oldB := systemctl, isRoot, unitOptions, binTarget
	systemctl, isRoot = f.run, func() bool { return true }
	unitOptions = provision.UnitOptions{UnitDir: filepath.Join(root, "systemd"), PolkitDir: filepath.Join(root, "polkit")}
	binTarget = filepath.Join(root, "bin", "vulnetix-sensor")
	t.Cleanup(func() { systemctl, isRoot, unitOptions, binTarget = oldS, oldR, oldU, oldB })
	t.Setenv("CREDENTIALS_DIRECTORY", "")

	return f, root
}

// site is a fake provisioning API.
type site struct {
	protection string
	uninstall  []string
	goodbyes   []map[string]string
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/runtime/provisioning/enroll":
		if r.Header.Get("Authorization") != "ApiKey alice:hmac" {
			w.WriteHeader(http.StatusForbidden)

			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deviceUuid": "dev-1", "profile": map[string]string{"uuid": "p-1", "name": "Laptops"},
			"credential": map[string]string{"scheme": "Sensor", "value": "dev-1:secret"},
			"config":     map[string]any{"mode": "guard", "protection": s.protection, "feeds": []string{"https://f"}},
			"configEtag": "etag-1",
		})
	case "/v1/runtime/provisioning/uninstall":
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.uninstall = append(s.uninstall, in["code"])
		if s.protection == "locked" && in["code"] != "123456" {
			w.WriteHeader(http.StatusForbidden)

			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	case "/v1/runtime/sensors/goodbye":
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.goodbyes = append(s.goodbyes, in)
		_, _ = w.Write([]byte(`{"ok":true}`))
	default:
		http.NotFound(w, r)
	}
}

func TestEnrollThenUninstall(t *testing.T) {
	for _, protection := range []string{"standard", "hardened", "locked"} {
		t.Run(protection, func(t *testing.T) {
			sys, root := withFakeSystem(t)
			s := &site{protection: protection}
			srv := httptest.NewServer(s)
			defer srv.Close()
			configDir, stateDir := filepath.Join(root, "etc"), filepath.Join(root, "state")
			t.Setenv("VULNETIX_API_KEY", "")
			t.Setenv("VULNETIX_ORG_ID", "")

			err := enrollCmd([]string{"--config-dir", configDir, "--state-dir", stateDir, "--endpoint", srv.URL,
				"--api-key", "hmac", "--org-id", "alice"})
			if err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(filepath.Join(configDir, "credential"))
			if err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("credential: %v %v", st, err)
			}
			cred, _ := provision.Store{Dir: configDir}.LoadCredential()
			if cred.AuthHeader() != "Sensor dev-1:secret" || cred.Endpoint != srv.URL {
				t.Fatalf("credential = %+v", cred)
			}
			unit, err := os.ReadFile(filepath.Join(unitOptions.UnitDir, provision.ServiceUnit))
			if err != nil || !strings.Contains(string(unit), "--config-dir "+configDir) {
				t.Fatalf("unit: %v\n%s", err, unit)
			}
			_, polkitErr := os.Stat(unitOptions.PolkitRulePath())
			if (polkitErr == nil) != (protection != "standard") {
				t.Fatalf("polkit rule present = %v for %s", polkitErr == nil, protection)
			}
			if !sys.called("enable", "--now", provision.ServiceUnit) || !sys.called("enable", "--now", provision.GuardTimerUnit) {
				t.Fatalf("calls = %v", sys.calls)
			}
			if _, err := os.Stat(binTarget); err != nil {
				t.Fatalf("binary not installed: %v", err)
			}

			if protection == "locked" {
				if err := uninstallCmd([]string{"--config-dir", configDir, "--state-dir", stateDir}); err == nil || !strings.Contains(err.Error(), "--code") {
					t.Fatalf("a locked uninstall with no code: %v", err)
				}
				if err := uninstallCmd([]string{"--config-dir", configDir, "--state-dir", stateDir, "--code", "wrong"}); err == nil {
					t.Fatal("a wrong code must stop the uninstall")
				}
				if _, err := os.Stat(filepath.Join(configDir, "credential")); err != nil {
					t.Fatal("a refused uninstall removes nothing")
				}
				if (provision.Store{Dir: configDir}).Uninstalling() {
					t.Fatal("a refused uninstall clears its marker")
				}
			}
			code := ""
			if protection == "locked" {
				code = "123456"
			}
			if err := uninstallCmd([]string{"--config-dir", configDir, "--state-dir", stateDir, "--code", code}); err != nil {
				t.Fatal(err)
			}
			if s.uninstall[len(s.uninstall)-1] != code {
				t.Fatalf("uninstall codes sent = %v", s.uninstall)
			}
			if len(s.goodbyes) == 0 || s.goodbyes[len(s.goodbyes)-1]["reason"] != "uninstall" {
				t.Fatalf("goodbyes = %v", s.goodbyes)
			}
			for _, p := range append(unitOptions.UnitPaths(), filepath.Join(configDir, "credential"), filepath.Join(configDir, "config.json")) {
				if _, err := os.Stat(p); err == nil {
					t.Errorf("%s left behind", p)
				}
			}
			if !sys.called("stop", provision.ServiceUnit) {
				t.Fatalf("service not stopped: %v", sys.calls)
			}
		})
	}
}

func TestGuardCheckRestoresAHardenedSensor(t *testing.T) {
	sys, root := withFakeSystem(t)
	s := &site{}
	srv := httptest.NewServer(s)
	defer srv.Close()
	store := provision.Store{Dir: filepath.Join(root, "etc")}
	stateDir := filepath.Join(root, "state")
	_ = os.MkdirAll(stateDir, 0o700)
	_ = os.WriteFile(filepath.Join(stateDir, "sensor-key"), []byte("sk\n"), 0o600)
	_ = store.SaveCredential(provision.Credential{Scheme: "Sensor", Value: "d:s", DeviceUUID: "d", Endpoint: srv.URL})
	_ = store.SaveSnapshot(provision.Snapshot{Config: provision.Config{Protection: "hardened"}})
	sys.enabled = "masked"

	if err := guardCheckCmd([]string{"--config-dir", store.Dir, "--state-dir", stateDir}); err != nil {
		t.Fatal(err)
	}
	if !sys.called("unmask", provision.ServiceUnit) || !sys.called("start", provision.ServiceUnit) {
		t.Fatalf("calls = %v", sys.calls)
	}
	if len(s.goodbyes) != 1 || s.goodbyes[0]["reason"] != "stop" || !strings.Contains(s.goodbyes[0]["detail"], "restored by guard") {
		t.Fatalf("goodbyes = %v", s.goodbyes)
	}
	if _, err := os.Stat(unitOptions.PolkitRulePath()); err != nil {
		t.Fatal("the guard writes the units the profile asks for")
	}

	// Standard: the guard keeps the units in step and restores nothing.
	sys.calls, sys.active = nil, "inactive"
	_ = store.SaveSnapshot(provision.Snapshot{Config: provision.Config{Protection: "standard"}})
	if err := guardCheckCmd([]string{"--config-dir", store.Dir, "--state-dir", stateDir}); err != nil {
		t.Fatal(err)
	}
	if sys.called("start", provision.ServiceUnit) {
		t.Fatal("a standard sensor that was stopped stays stopped")
	}
	if _, err := os.Stat(unitOptions.PolkitRulePath()); err == nil {
		t.Fatal("dropping to standard removes the polkit rule")
	}
}

func TestEnrollPrintWritesNothing(t *testing.T) {
	_, root := withFakeSystem(t)
	isRoot = func() bool { return false }
	if err := enrollCmd([]string{"--config-dir", filepath.Join(root, "etc"), "--state-dir", filepath.Join(root, "s"), "--print", "--protection", "hardened"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc")); err == nil {
		t.Fatal("--print wrote files")
	}
	if err := enrollCmd([]string{"--config-dir", filepath.Join(root, "etc")}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("enroll without root: %v", err)
	}
}
