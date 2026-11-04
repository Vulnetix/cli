package provision

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Unit names.
const (
	ServiceUnit      = "vulnetix-sensor.service"
	GuardServiceUnit = "vulnetix-sensor-guard.service"
	GuardTimerUnit   = "vulnetix-sensor-guard.timer"
	PolkitRuleName   = "50-vulnetix-sensor.rules"
)

// DefaultBinPath is where enroll installs the binary.
const DefaultBinPath = "/usr/local/bin/vulnetix-sensor"

// LegacyEnvFile is install.sh's credential file, still read when present.
const LegacyEnvFile = "/etc/vulnetix-sensor.env"

// WatchdogSec is the hardened unit's watchdog; the sensor pings at half of it.
const WatchdogSec = 30

// File is one file the units consist of.
type File struct {
	Path    string
	Mode    os.FileMode
	Content string
}

// UnitOptions says where the files go. The zero value is the real system.
type UnitOptions struct {
	ConfigDir string // default /etc/vulnetix-sensor
	UnitDir   string // default /etc/systemd/system
	PolkitDir string // default /etc/polkit-1/rules.d
}

func (o UnitOptions) withDefaults() UnitOptions {
	if o.ConfigDir == "" {
		o.ConfigDir = DefaultDir
	}
	if o.UnitDir == "" {
		o.UnitDir = "/etc/systemd/system"
	}
	if o.PolkitDir == "" {
		o.PolkitDir = "/etc/polkit-1/rules.d"
	}

	return o
}

// PolkitRulePath is where the hardened polkit rule goes.
func (o UnitOptions) PolkitRulePath() string {
	return filepath.Join(o.withDefaults().PolkitDir, PolkitRuleName)
}

// UnitPaths is every file RenderUnits can write, for removal.
func (o UnitOptions) UnitPaths() []string {
	o = o.withDefaults()

	return []string{
		filepath.Join(o.UnitDir, ServiceUnit),
		filepath.Join(o.UnitDir, GuardServiceUnit),
		filepath.Join(o.UnitDir, GuardTimerUnit),
		o.PolkitRulePath(),
	}
}

// unitCapabilities is all the sensor service holds: binding a privileged
// listen port, and reading other processes' /proc entries for the in-use
// package inventory, which a dynamic user cannot otherwise do.
const unitCapabilities = "CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH"

// RenderUnits returns the systemd units (and, from hardened up, the polkit
// rule) for cfg's protection level, running binPath.
//
// Every level gets the sensor service and the guard timer. The guard runs as
// root once a minute: it keeps the units in step with the profile (so a
// profile raised to hardened takes effect without a reinstall) and, from
// hardened up, restores a sensor that was stopped, disabled or masked.
//
// The service runs as a dynamic user, which cannot read the root-only
// credential, so systemd hands it over with LoadCredential=.
func RenderUnits(cfg Config, binPath string, opts ...UnitOptions) []File {
	var o UnitOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	o = o.withDefaults()
	if binPath == "" {
		binPath = DefaultBinPath
	}
	level := cfg.Level()
	hardened := level != Standard
	refuseStop := hardened && !cfg.UserMayStop()

	var svc strings.Builder
	fmt.Fprintf(&svc, "# Written by vulnetix-sensor enroll (protection: %s). Edits are replaced by\n# the guard when the profile changes; change the profile in the console.\n", level)
	svc.WriteString("[Unit]\nDescription=Vulnetix runtime sensor\nAfter=network-online.target\nWants=network-online.target\n")
	if hardened {
		svc.WriteString("StartLimitIntervalSec=0\n")
	}
	if refuseStop {
		svc.WriteString("RefuseManualStop=yes\n")
	}
	svc.WriteString("\n[Service]\n")
	if hardened {
		fmt.Fprintf(&svc, "Type=notify\nNotifyAccess=main\nWatchdogSec=%d\n", WatchdogSec)
	} else {
		svc.WriteString("Type=simple\n")
	}
	fmt.Fprintf(&svc, "EnvironmentFile=-%s\n", LegacyEnvFile)
	fmt.Fprintf(&svc, "LoadCredential=credential:%s\n", filepath.Join(o.ConfigDir, credentialFile))
	fmt.Fprintf(&svc, "ExecStart=%s --config-dir %s\n", binPath, o.ConfigDir)
	svc.WriteString(`Restart=always
RestartSec=5
StateDirectory=vulnetix-sensor
DynamicUser=yes
# CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH let the in-use package inventory
# read which packages other users' processes map (/proc/<pid>/maps and the
# exe links need PTRACE_MODE_READ). Read-only: the sensor attaches to nothing.
AmbientCapabilities=` + unitCapabilities + `
CapabilityBoundingSet=` + unitCapabilities + `
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=256M

[Install]
WantedBy=multi-user.target
`)

	guardSvc := fmt.Sprintf(`# Written by vulnetix-sensor enroll.
[Unit]
Description=Vulnetix sensor guard: keeps the sensor's units in step with its profile
After=network-online.target

[Service]
Type=oneshot
# The previous binary checks first, so a release that cannot start (and so cannot
# run its own guard) is still rolled back. Absent or unable to run is ignored.
# It is a flag, not a subcommand: a previous binary that predates the check
# rejects the flag and exits, where a subcommand it did not know would have
# started it as a second sensor and hung this unit.
ExecStartPre=-%s.prev --guard-rescue --config-dir %s
ExecStart=%s guard-check --config-dir %s
# A guard that does not finish must not stop the next one from running.
TimeoutStartSec=300
# The same environment as the sensor, so a proxy set there reaches the update
# download too.
EnvironmentFile=-%s
`, binPath, o.ConfigDir, binPath, o.ConfigDir, LegacyEnvFile)

	var timer strings.Builder
	timer.WriteString("# Written by vulnetix-sensor enroll.\n[Unit]\nDescription=Run the Vulnetix sensor guard every minute\n")
	if refuseStop {
		timer.WriteString("RefuseManualStop=yes\n")
	}
	timer.WriteString(`
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
`)

	files := []File{
		{Path: filepath.Join(o.UnitDir, ServiceUnit), Mode: 0o644, Content: svc.String()},
		{Path: filepath.Join(o.UnitDir, GuardServiceUnit), Mode: 0o644, Content: guardSvc},
		{Path: filepath.Join(o.UnitDir, GuardTimerUnit), Mode: 0o644, Content: timer.String()},
	}
	if hardened {
		files = append(files, File{Path: o.PolkitRulePath(), Mode: 0o644, Content: PolkitRule(level)})
	}

	return files
}

// PolkitRule refuses anyone but root starting, stopping, masking or
// enabling the sensor and its guard. systemd names the unit for
// manage-units; it does not for manage-unit-files (enable, disable, mask act
// on files), so that action is refused for every unit to anyone but root:
// on a hardened host, an administrator changes unit files with sudo.
func PolkitRule(level string) string {
	return fmt.Sprintf(`// Written by vulnetix-sensor enroll (protection: %s).
// Only root may manage the Vulnetix sensor and its guard.
polkit.addRule(function(action, subject) {
    if (subject.user == "root") {
        return polkit.Result.NOT_HANDLED;
    }
    if (action.id == "org.freedesktop.systemd1.manage-units") {
        var unit = action.lookup("unit") || "";
        if (unit == "vulnetix-sensor.service" || unit.indexOf("vulnetix-sensor-guard.") == 0) {
            return polkit.Result.NO;
        }
    }
    if (action.id == "org.freedesktop.systemd1.manage-unit-files") {
        var unit = action.lookup("unit") || "";
        if (unit == "" || unit == "vulnetix-sensor.service" || unit.indexOf("vulnetix-sensor-guard.") == 0) {
            return polkit.Result.NO;
        }
    }
    return polkit.Result.NOT_HANDLED;
});
`, level)
}
