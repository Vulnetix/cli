package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The update-safety rules the scenario tests in updatehealth_test.go do not
// reach directly: restorePrev's three outcomes, which health stamps count as
// proof, the bad list on a failed rollback, and the writable check.

func TestRestorePrev(t *testing.T) {
	t.Run("no previous binary", func(t *testing.T) {
		_, target := installed(t)
		err := restorePrev(target)
		if err == nil || !strings.Contains(err.Error(), "no previous binary to restore") {
			t.Fatalf("err = %v", err)
		}
		if b, _ := os.ReadFile(target); string(b) != "old" {
			t.Fatalf("the installed binary must be left alone: %q", b)
		}
	})

	t.Run("empty previous binary", func(t *testing.T) {
		_, target := installed(t)
		if err := os.WriteFile(target+".prev", nil, 0o755); err != nil {
			t.Fatal(err)
		}
		err := restorePrev(target)
		if err == nil || !strings.Contains(err.Error(), "the previous binary is empty") {
			t.Fatalf("err = %v", err)
		}
		if b, _ := os.ReadFile(target); string(b) != "old" {
			t.Fatalf("an empty .prev must never replace the binary: %q", b)
		}
	})

	t.Run("good previous binary", func(t *testing.T) {
		_, target := installed(t)
		if err := os.WriteFile(target+".prev", []byte("previous"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := restorePrev(target); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(target)
		if err != nil || string(b) != "previous" {
			t.Fatalf("target = %q, %v", b, err)
		}
		info, err := os.Stat(target)
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("the restored binary must be executable: %v %v", info.Mode(), err)
		}
		if _, err := os.Stat(target + ".prev"); err != nil {
			t.Fatalf(".prev is kept: %v", err)
		}
	})
}

// Only a stamp from the new version, written after the swap, proves it.
func TestOnlyAFreshStampFromTheNewVersionConfirms(t *testing.T) {
	swapped := time.Now().Add(-2 * time.Minute)
	for _, tt := range []struct {
		name  string
		stamp healthState
		want  string
	}{
		{"new version after the swap", healthState{Version: "v3.200.0", At: swapped.Add(time.Second)}, "ok"},
		{"new version at the swap", healthState{Version: "v3.200.0", At: swapped}, "ok"},
		{"new version before the swap", healthState{Version: "v3.200.0", At: swapped.Add(-time.Second)}, ""},
		{"old version after the swap", healthState{Version: "v3.158.0", At: swapped.Add(time.Second)}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir, target := installed(t)
			saveUpdateState(dir, updateState{Pending: &pendingUpdate{From: "v3.158.0", To: "v3.200.0", At: swapped}})
			writeStamp(t, dir, tt.stamp)
			// Two minutes in, a healthy unit, the server reachable: inside the window.
			action, _, err := reconcilePending(dir, target, swapped.Add(2*time.Minute), false, true)
			if err != nil || action != tt.want {
				t.Fatalf("action = %q, %v; want %q", action, err, tt.want)
			}
			if pending := loadUpdateState(dir).Pending; (pending == nil) != (tt.want == "ok") {
				t.Fatalf("pending = %+v after %q", pending, action)
			}
		})
	}
}

func writeStamp(t *testing.T, dir string, h healthState) {
	t.Helper()
	b := []byte(`{"version":"` + h.Version + `","at":"` + h.At.Format(time.RFC3339Nano) + `"}`)
	if err := os.WriteFile(filepath.Join(dir, healthStamp), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNothingPendingIsNoVerdict(t *testing.T) {
	dir, target := installed(t)
	action, out, err := reconcilePending(dir, target, time.Now(), true, false)
	if action != "" || out != nil || err != nil {
		t.Fatalf("got %q %+v %v", action, out, err)
	}
}

// A rollback that cannot restore still marks the release bad, so the guard does
// not take it again, and says why in the outcome.
func TestAFailedRollbackStillMarksTheReleaseBad(t *testing.T) {
	dir, target := installed(t)
	saveUpdateState(dir, updateState{
		Bad:     []string{"v3.199.0"},
		Pending: &pendingUpdate{From: "v3.158.0", To: "v3.200.0", At: time.Now().Add(-2 * time.Minute)},
	})
	_, out, err := reconcilePending(dir, target, time.Now(), true, true)
	if err == nil || out == nil || out.State != "failed" {
		t.Fatalf("got %+v %v", out, err)
	}
	if !strings.Contains(out.Reason, "the sensor unit failed") || !strings.Contains(out.Reason, "rollback failed: no previous binary") {
		t.Errorf("reason = %q", out.Reason)
	}
	st := loadUpdateState(dir)
	if st.Pending != nil || len(st.Bad) != 2 || st.Bad[1] != "v3.200.0" {
		t.Errorf("state = %+v", st)
	}
}

func TestUpdateSkipReasonNeedsAWritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "vulnetix-sensor")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if r := updateSkipReason(bin, bin); !strings.Contains(r, "not writable") {
		t.Errorf("a read-only install directory: %q", r)
	}
}
