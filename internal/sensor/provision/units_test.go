package provision

import (
	"strings"
	"testing"
)

func unitByName(files []File, suffix string) string {
	for _, f := range files {
		if strings.HasSuffix(f.Path, suffix) {
			return f.Content
		}
	}

	return ""
}

func TestRenderUnitsStandard(t *testing.T) {
	files := RenderUnits(Config{Protection: Standard}, "/usr/local/bin/vulnetix-sensor")
	svc := unitByName(files, ServiceUnit)
	for _, want := range []string{
		"LoadCredential=credential:/etc/vulnetix-sensor/credential",
		"ExecStart=/usr/local/bin/vulnetix-sensor --config-dir /etc/vulnetix-sensor",
		"EnvironmentFile=-/etc/vulnetix-sensor.env",
		"DynamicUser=yes", "StateDirectory=vulnetix-sensor", "Restart=always", "Type=simple",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n",
		"NoNewPrivileges=yes", "ProtectSystem=strict",
	} {
		if !strings.Contains(svc, want) {
			t.Errorf("standard unit lacks %q:\n%s", want, svc)
		}
	}
	for _, not := range []string{"RefuseManualStop", "WatchdogSec", "Type=notify", "StartLimitIntervalSec"} {
		if strings.Contains(svc, not) {
			t.Errorf("standard unit has %q", not)
		}
	}
	if unitByName(files, PolkitRuleName) != "" {
		t.Error("standard writes no polkit rule")
	}
	if !strings.Contains(unitByName(files, GuardServiceUnit), "guard-check --config-dir /etc/vulnetix-sensor") {
		t.Error("the guard runs guard-check")
	}
	if !strings.Contains(unitByName(files, GuardTimerUnit), "OnUnitActiveSec=1min") {
		t.Error("the guard runs every minute")
	}
}

func TestRenderUnitsHardened(t *testing.T) {
	for _, c := range []struct {
		cfg    Config
		refuse bool
	}{
		{Config{Protection: Hardened}, true},
		{Config{Protection: Hardened, AllowUserStop: true}, false},
		{Config{Protection: Locked, AllowUserStop: true}, true},
	} {
		files := RenderUnits(c.cfg, "/usr/local/bin/vulnetix-sensor", UnitOptions{ConfigDir: "/tmp/x", UnitDir: "/u", PolkitDir: "/p"})
		svc := unitByName(files, ServiceUnit)
		for _, want := range []string{"StartLimitIntervalSec=0", "Type=notify", "WatchdogSec=30", "NotifyAccess=main", "LoadCredential=credential:/tmp/x/credential", "DynamicUser=yes", "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n", "NoNewPrivileges=yes"} {
			if !strings.Contains(svc, want) {
				t.Errorf("%+v: unit lacks %q", c.cfg, want)
			}
		}
		if got := strings.Contains(svc, "RefuseManualStop=yes"); got != c.refuse {
			t.Errorf("%+v: RefuseManualStop present = %v, want %v", c.cfg, got, c.refuse)
		}
		if got := strings.Contains(unitByName(files, GuardTimerUnit), "RefuseManualStop=yes"); got != c.refuse {
			t.Errorf("%+v: timer RefuseManualStop = %v", c.cfg, got)
		}
		var rule File
		for _, f := range files {
			if f.Path == "/p/"+PolkitRuleName {
				rule = f
			}
		}
		for _, want := range []string{
			`"org.freedesktop.systemd1.manage-units"`, `"org.freedesktop.systemd1.manage-unit-files"`,
			`subject.user == "root"`, `"vulnetix-sensor.service"`, `"vulnetix-sensor-guard."`, "polkit.Result.NO",
		} {
			if !strings.Contains(rule.Content, want) {
				t.Errorf("%+v: polkit rule lacks %s", c.cfg, want)
			}
		}
	}
}

func TestUserMayStop(t *testing.T) {
	if !(Config{}).UserMayStop() || (Config{Protection: Hardened}).UserMayStop() ||
		!(Config{Protection: Hardened, AllowUserStop: true}).UserMayStop() ||
		(Config{Protection: Locked, AllowUserStop: true}).UserMayStop() {
		t.Fatal("standard may stop, hardened only with allowUserStop, locked never")
	}
	if (Config{Protection: "bogus"}).Level() != Standard {
		t.Fatal("an unknown level is standard")
	}
}
