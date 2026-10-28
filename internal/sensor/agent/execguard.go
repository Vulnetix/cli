package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vulnetix/cli/v3/internal/sensor/execguard"
	"github.com/vulnetix/cli/v3/internal/sensor/execwatch"
)

// errRefused is the answer the guard turns into EPERM.
var errRefused = errors.New("refused by a Vulnetix rule")

// runExecGuard runs the workload under the seccomp exec guard and sends its
// exit code on done. Every exec the workload makes is checked with the same
// rules as the Tetragon watcher, before it runs.
func (a *Agent) runExecGuard(done chan<- int) {
	w := &execwatch.Watcher{Root: "/", Rules: a.Rules.Load, Verdicts: a.Verdicts, Report: a.Enqueue}
	code, err := execguard.Run(a.cfg.ExecGuard, func(e execguard.Exec) error {
		if w.Gate(guardExec(e)) {
			return errRefused
		}

		return nil
	})
	if err != nil {
		a.cfg.Logf("sensor: exec guard: %v", err)
		code = 126
	}
	done <- code
}

// guardExec describes a pending exec the way Tetragon describes one that ran:
// the caller (still the image in /proc/<pid>/exe) is the parent.
func guardExec(e execguard.Exec) execwatch.Exec {
	proc := filepath.Join("/proc", strconv.Itoa(e.PID))
	out := execwatch.Exec{PID: e.PID, Binary: e.Path, PreExec: true}
	if len(e.Argv) > 1 {
		out.Arguments = strings.Join(e.Argv[1:], " ")
	}
	out.Cwd, _ = os.Readlink(filepath.Join(proc, "cwd"))
	out.ParentBinary, _ = os.Readlink(filepath.Join(proc, "exe"))
	if cmdline, err := os.ReadFile(filepath.Join(proc, "cmdline")); err == nil {
		parts := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(parts) > 1 {
			out.ParentArguments = strings.Join(parts[1:], " ")
		}
	}

	return out
}
