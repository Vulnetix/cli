//go:build linux && (amd64 || arm64)

package execguard

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

func TestMain(m *testing.M) {
	MaybeChild()
	os.Exit(m.Run())
}

// These run a real workload under a real seccomp filter, so they need a
// kernel with user notifications (5.0 and later) and a shell.
func requireShell(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}

	return sh
}

func TestRunAllowsAndRefusesExecs(t *testing.T) {
	sh := requireShell(t)
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true")
	}
	// By full path: "false" alone is a shell builtin and never calls exec.
	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false")
	}
	var mu sync.Mutex
	var seen []Exec
	decide := func(e Exec) error {
		mu.Lock()
		seen = append(seen, e)
		mu.Unlock()
		if strings.HasSuffix(e.Path, "/false") {
			return errors.New("refused")
		}

		return nil
	}

	// true runs; false is refused, and sh reports 126 for it.
	code, err := Run([]string{sh, "-c", truePath + " allowed-arg; " + falsePath + "; [ $? = 126 ] || exit 1; exit 7"}, decide)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	mu.Lock()
	defer mu.Unlock()
	var sawTrue, sawFalse bool
	for _, e := range seen {
		if e.Path == truePath && len(e.Argv) == 2 && e.Argv[1] == "allowed-arg" {
			sawTrue = true
		}
		if strings.HasSuffix(e.Path, "/false") {
			sawFalse = true
		}
	}
	if !sawTrue || !sawFalse {
		t.Fatalf("decisions saw %+v", seen)
	}
	for _, e := range seen {
		if e.Path == sh {
			t.Fatal("the workload's own start is allowed without asking")
		}
	}
}

func TestRunPassesTheExitCodeThrough(t *testing.T) {
	sh := requireShell(t)
	code, err := Run([]string{sh, "-c", "exit 3"}, nil)
	if err != nil || code != 3 {
		t.Fatalf("code = %d, err = %v", code, err)
	}
}

func TestRefusedExecFailsWithEPERM(t *testing.T) {
	sh := requireShell(t)
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	out.Close()
	code, err := Run([]string{sh, "-c", "/bin/ls / >/dev/null 2>" + out.Name() + "; exit $?"}, func(e Exec) error {
		return errors.New("no")
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := os.ReadFile(out.Name())
	if code != 126 || !strings.Contains(strings.ToLower(string(msg)), "not permitted") {
		t.Fatalf("code = %d, stderr = %q", code, msg)
	}
}

func TestFilterIsShort(t *testing.T) {
	if n := len(filter()); n != 8 {
		t.Fatalf("filter has %d instructions", n)
	}
}
