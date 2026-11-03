package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installed lays out a binary with a kept previous one, as an update leaves it.
func installed(t *testing.T) (dir, target string) {
	t.Helper()
	dir = t.TempDir()
	target = filepath.Join(dir, "vulnetix-sensor")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	return dir, target
}

func TestACrossingOfAMajorVersionIsHeldUnlessTheProfileAllowsIt(t *testing.T) {
	srv := fakeRelease(t, "v4.0.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir, target := installed(t)
	now := time.Now()

	if tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.167.0", target, dir, now); tag != "" || err != nil {
		t.Fatalf("a new major version must be held: %q %v", tag, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Fatal("the binary changed across a major version")
	}
	st := loadUpdateState(dir)
	if !strings.Contains(st.Held, "allowMajorUpdate") || st.Latest != "v4.0.0" {
		t.Fatalf("the hold says why and what is waiting: %+v", st)
	}

	// The profile allows it, and the next check (past the interval) takes it.
	if tag, err := maybeSelfUpdate(context.Background(), true, true, "v3.167.0", target, dir, now.Add(7*time.Hour)); tag != "v4.0.0" || err != nil {
		t.Fatalf("allowMajorUpdate takes the release: %q %v", tag, err)
	}
	// A minor or patch release within the major version was never held.
	if crossesMajor("v4.5.0", "v4.7.1") || !crossesMajor("v3.167.0", "v4.0.0") {
		t.Fatal("crossesMajor")
	}
}

func TestAnUpdateIsPendingUntilTheNewSensorReportsAndThenConfirmed(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir, target := installed(t)
	now := time.Now()
	if tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now); tag != "v3.200.0" || err != nil {
		t.Fatalf("%q %v", tag, err)
	}
	st := loadUpdateState(dir)
	if st.Pending == nil || st.Pending.From != "v3.158.0" || st.Pending.To != "v3.200.0" {
		t.Fatalf("the swap leaves the update pending: %+v", st)
	}

	// While it is pending no further release is taken, however long since the check.
	if tag, _ := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now.Add(24*time.Hour)); tag != "" {
		t.Fatalf("an unproven update must not be stacked on: %q", tag)
	}
	// Inside the window, with no report and a healthy unit, nothing happens.
	if action, _, _ := reconcilePending(dir, target, now.Add(2*time.Minute), false, true); action != "" {
		t.Fatalf("too early to judge: %q", action)
	}
	// The new sensor reports: confirmed.
	if err := writeHealth(dir, "v3.200.0"); err != nil {
		t.Fatal(err)
	}
	action, out, err := reconcilePending(dir, target, time.Now().Add(time.Minute), false, true)
	if action != "ok" || err != nil || out == nil || out.State != "ok" {
		t.Fatalf("a reporting sensor confirms the update: %q %+v %v", action, out, err)
	}
	if st := loadUpdateState(dir); st.Pending != nil || st.Outcome == nil || st.Outcome.State != "ok" {
		t.Fatalf("pending is cleared: %+v", st)
	}
	if b, _ := os.ReadFile(target); string(b) == "old" {
		t.Fatal("a confirmed update keeps the new binary")
	}
}

func TestASensorThatNeverReportsIsRolledBackAndNeverTakenAgain(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir, target := installed(t)
	now := time.Now()
	if tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now); tag != "v3.200.0" || err != nil {
		t.Fatalf("%q %v", tag, err)
	}
	// A stale stamp from the previous version is not proof for the new one.
	if err := writeHealth(dir, "v3.158.0"); err != nil {
		t.Fatal(err)
	}

	action, out, err := reconcilePending(dir, target, now.Add(6*time.Minute), false, true)
	if action != "rolled_back" || err != nil || out == nil || out.State != "rolled_back" || !strings.Contains(out.Reason, "v3.200.0") {
		t.Fatalf("a silent release is rolled back: %q %+v %v", action, out, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Fatalf("the previous binary is restored, target holds %q", b)
	}
	if b, _ := os.ReadFile(target + ".prev"); string(b) != "old" {
		t.Fatal("the previous binary stays available")
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("the restored binary is executable: %v %v", fi, err)
	}
	st := loadUpdateState(dir)
	if st.Pending != nil || !containsString(st.Bad, "v3.200.0") {
		t.Fatalf("the release is remembered as bad: %+v", st)
	}

	// The same release is not taken again, however often the check runs.
	if tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now.Add(48*time.Hour)); tag != "" || err != nil {
		t.Fatalf("a rolled-back release must not come back: %q %v", tag, err)
	}
	if st := loadUpdateState(dir); !strings.Contains(st.Held, "rolled back") {
		t.Fatalf("and the hold says so: %+v", st)
	}
	// A newer release is taken.
	srv2 := fakeRelease(t, "v3.201.0", false)
	releaseBaseURL = srv2.URL
	if tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now.Add(72*time.Hour)); tag != "v3.201.0" || err != nil {
		t.Fatalf("a newer release is taken: %q %v", tag, err)
	}
}

func TestAFailedUnitIsRolledBackAfterOneMinuteNotFive(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir, target := installed(t)
	now := time.Now()
	if _, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now); err != nil {
		t.Fatal(err)
	}
	if action, _, _ := reconcilePending(dir, target, now.Add(20*time.Second), true, true); action != "" {
		t.Fatalf("a unit still starting is not judged yet: %q", action)
	}
	action, out, err := reconcilePending(dir, target, now.Add(90*time.Second), true, true)
	if action != "rolled_back" || err != nil || !strings.Contains(out.Reason, "unit failed") {
		t.Fatalf("a failed unit rolls back at once: %q %+v %v", action, out, err)
	}
}

func TestARollbackWithNothingToRestoreIsReportedNotSilent(t *testing.T) {
	dir, target := installed(t)
	saveUpdateState(dir, updateState{Pending: &pendingUpdate{From: "v3.158.0", To: "v3.200.0", At: time.Now().Add(-10 * time.Minute)}})
	action, out, err := reconcilePending(dir, target, time.Now(), false, true)
	if action == "rolled_back" || err == nil || out == nil || out.State != "failed" {
		t.Fatalf("no .prev: the failure is an outcome and an error, not a pretend success: %q %+v %v", action, out, err)
	}
	if st := loadUpdateState(dir); st.Pending != nil {
		t.Fatal("it must not retry the same rollback every minute forever")
	}
}

func TestAnUpdateThatCannotKeepThePreviousBinaryIsNotMade(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir, target := installed(t)
	// A directory where the .prev file must go: it cannot be written.
	if err := os.Mkdir(target+".prev", 0o755); err != nil {
		t.Fatal(err)
	}
	tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, time.Now())
	if err == nil || tag != "" {
		t.Fatalf("an update that cannot be undone must not be made: %q %v", tag, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Fatal("the binary changed")
	}
	if st := loadUpdateState(dir); st.Pending != nil {
		t.Fatalf("no pending update for a swap that did not happen: %+v", st.Pending)
	}
}

func TestOnlyOneGuardUpdatesAtATime(t *testing.T) {
	dir := t.TempDir()
	unlock, ok := lockUpdate(dir)
	if !ok {
		t.Fatal("the first lock is taken")
	}
	if _, ok2 := lockUpdate(dir); ok2 {
		t.Fatal("a second guard must not run while the first holds the lock")
	}
	unlock()
	if u3, ok3 := lockUpdate(dir); !ok3 {
		t.Fatal("the lock is free again")
	} else {
		u3()
	}
}

// A network outage right after an update must not condemn a good release.
func TestAnOutageDoesNotMakeAGoodReleaseBad(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir, target := installed(t)
	now := time.Now()
	if _, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now); err != nil {
		t.Fatal(err)
	}
	// Silent past the window, but the host cannot reach the server at all.
	if action, _, _ := reconcilePending(dir, target, now.Add(20*time.Minute), false, false); action != "" {
		t.Fatalf("no verdict while the server is unreachable: %q", action)
	}
	if st := loadUpdateState(dir); st.Pending == nil || len(st.Bad) != 0 {
		t.Fatalf("still pending, nothing marked bad: %+v", st)
	}
	// The network comes back and the sensor reports: confirmed, not rolled back.
	if err := writeHealth(dir, "v3.200.0"); err != nil {
		t.Fatal(err)
	}
	if action, _, _ := reconcilePending(dir, target, now.Add(25*time.Minute), false, true); action != "ok" {
		t.Fatalf("a sensor that reported after the outage is confirmed: %q", action)
	}
	// An outage that outlasts any reasonable wait is judged.
	dir2, target2 := installed(t)
	srv2 := fakeRelease(t, "v3.201.0", false)
	releaseBaseURL = srv2.URL
	if _, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target2, dir2, now); err != nil {
		t.Fatal(err)
	}
	if action, _, _ := reconcilePending(dir2, target2, now.Add(61*time.Minute), false, false); action != "rolled_back" {
		t.Fatalf("an hour of silence is judged whatever the network: %q", action)
	}
	// A crashed unit is the release's fault whatever the network is doing.
	dir3, target3 := installed(t)
	if _, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target3, dir3, now); err != nil {
		t.Fatal(err)
	}
	if action, _, _ := reconcilePending(dir3, target3, now.Add(2*time.Minute), true, false); action != "rolled_back" {
		t.Fatalf("a failed unit rolls back even with the network down: %q", action)
	}
}
