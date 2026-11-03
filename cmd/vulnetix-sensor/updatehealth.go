package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/provision"
)

// An update is not finished when the binary is swapped. The new sensor must
// reach the server: the sensor writes health.json once its first report is
// accepted, and until it does the update is pending. A release that cannot
// start, that crashes, or that the server turns away is detected by the absence
// of that stamp, and the previous binary is put back.
//
// Two things check. The guard (the new binary, once a minute) does, which covers
// a release that starts but cannot report. A release that cannot start at all
// also takes the guard with it, because the guard is the same binary, so the
// guard unit first runs the previous binary's guard-rescue
// (units.go ExecStartPre), which does only this check.

const (
	healthStamp = "health.json"
	// healthMinWait is how long a new sensor gets before a failed unit counts
	// as a failed update; healthWindow is how long before a silent one does.
	healthMinWait = time.Minute
	healthWindow  = 5 * time.Minute
	// healthOutage is how long a verdict waits while the server is unreachable.
	healthOutage = time.Hour
)

type pendingUpdate struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

// updateOutcome is what the last update came to: ok, rolled_back or failed.
type updateOutcome struct {
	State  string    `json:"state"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

type healthState struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

// writeHealth is the sensor saying it is up and the server accepted it.
func writeHealth(stateDir, version string) error {
	b, err := json.Marshal(healthState{Version: version, At: time.Now()})
	if err != nil {
		return err
	}

	return writeFileAtomic(filepath.Join(stateDir, healthStamp), b, 0o644)
}

func loadHealth(stateDir string) healthState {
	var h healthState
	if b, err := os.ReadFile(filepath.Join(stateDir, healthStamp)); err == nil {
		_ = json.Unmarshal(b, &h)
	}

	return h
}

// writeFileAtomic writes to a temporary file in the same directory, syncs it and
// renames it into place, so a reader sees the old file or the new one.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vulnetix-write.*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}

// lockUpdate takes the update lock in the state directory without waiting. The
// guard runs every minute and the rescue runs before it; two at once would
// swap or restore the binary twice.
func lockUpdate(stateDir string) (unlock func(), ok bool) {
	f, err := os.OpenFile(filepath.Join(stateDir, ".update.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, true // no lock is better than no update check
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()

		return func() {}, false
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true
}

// restorePrev puts target.prev back as target. It is the same durable rename as
// an update, and it leaves target.prev in place.
func restorePrev(target string) error {
	prev, err := os.ReadFile(target + ".prev")
	if err != nil {
		return fmt.Errorf("no previous binary to restore: %w", err)
	}
	if len(prev) == 0 {
		return fmt.Errorf("the previous binary is empty")
	}

	return writeFileAtomic(target, prev, 0o755)
}

// reconcilePending resolves a pending update. It returns "ok" when the new
// sensor proved itself, "rolled_back" when it did not and the previous binary
// was restored, and "" while the update is still inside its window or nothing
// is pending. serviceFailed is whether systemd reports the sensor unit failed.
func reconcilePending(stateDir, target string, now time.Time, serviceFailed, serverReachable bool) (string, *updateOutcome, error) {
	st := loadUpdateState(stateDir)
	if st.Pending == nil {
		return "", nil, nil
	}
	p := *st.Pending
	h := loadHealth(stateDir)
	if h.Version == p.To && !h.At.Before(p.At) {
		st.Outcome = &updateOutcome{State: "ok", From: p.From, To: p.To, At: now}
		st.Pending = nil
		saveUpdateState(stateDir, st)

		return "ok", st.Outcome, nil
	}
	waited := now.Sub(p.At)
	if waited < healthMinWait || (waited < healthWindow && !serviceFailed) {
		return "", nil, nil
	}
	// A sensor that has not reported is only the release's fault if the host can
	// reach the server. During an outage the verdict waits (up to healthOutage),
	// so a good release is not marked bad for a network problem. A crashed unit
	// is the release's fault whatever the network is doing.
	if !serviceFailed && !serverReachable && waited < healthOutage {
		return "", nil, nil
	}
	reason := fmt.Sprintf("%s did not reach the server within %s", p.To, waited.Round(time.Second))
	if serviceFailed {
		reason = fmt.Sprintf("%s: the sensor unit failed", p.To)
	}
	if err := restorePrev(target); err != nil {
		st.Outcome = &updateOutcome{State: "failed", From: p.From, To: p.To, Reason: reason + "; rollback failed: " + err.Error(), At: now}
		st.Pending = nil
		st.Bad = append(st.Bad, p.To)
		saveUpdateState(stateDir, st)

		return "", st.Outcome, err
	}
	st.Bad = append(st.Bad, p.To)
	st.Outcome = &updateOutcome{State: "rolled_back", From: p.From, To: p.To, Reason: reason, At: now}
	st.Pending = nil
	saveUpdateState(stateDir, st)

	return "rolled_back", st.Outcome, nil
}

// serviceFailed is whether systemd reports the sensor unit failed.
func serviceFailed() bool {
	out, _ := systemctl("is-failed", provision.ServiceUnit)

	return out == "failed"
}

// announceOutcome puts a finished update right: after a rollback the sensor is
// restarted on the restored binary, and the server is told why the version
// changed (goodbye reason upgrade; the detail carries the rollback).
func announceOutcome(c commonFlags, store provision.Store, o *updateOutcome) {
	if o == nil {
		return
	}
	if o.State == "rolled_back" {
		_, _ = systemctl("reset-failed", provision.ServiceUnit)
		if isActive() {
			_, _ = systemctl("kill", "--kill-whom=main", "--signal=SIGHUP", provision.ServiceUnit)
		} else {
			_, _ = systemctl("start", provision.ServiceUnit)
		}
		fmt.Printf("guard: rolled back %s -> %s: %s\n", o.To, o.From, o.Reason)
	} else if o.State == "ok" {
		fmt.Printf("guard: update to %s confirmed\n", o.To)

		return
	}
	if cred, err := store.LoadCredential(); err == nil {
		if key := readSensorKey(*c.stateDir); key != "" {
			sayGoodbye(uplinkFor(c.endpointFor(cred), cred), key, "upgrade", "update "+o.State+": "+o.From+" to "+o.To+": "+o.Reason)
		}
	}
}

// guardRescueCmd is run by the guard unit before guard-check, from the PREVIOUS
// binary (target.prev). It does one thing: if the update the current binary
// came from has not proved itself, put the previous binary back. A release that
// cannot start cannot run its own guard, so this is what rescues it.
func guardRescueCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor guard-rescue", flag.ContinueOnError)
	c := defineCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := c.store()
	if !store.HasCredential() || store.Uninstalling() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil || !strings.HasSuffix(exe, ".prev") {
		return nil // only the kept previous binary rescues
	}
	target := strings.TrimSuffix(exe, ".prev")
	unlock, locked := lockUpdate(*c.stateDir)
	if !locked {
		return nil
	}
	defer unlock()
	action, outcome, err := reconcilePending(*c.stateDir, target, time.Now(), serviceFailed(), serverReachable(c, store))
	if err != nil {
		return err
	}
	if action == "rolled_back" {
		announceOutcome(c, store, outcome)
	}

	return nil
}

// serverReachable is whether this host can reach the Vulnetix server at all: any
// HTTP answer counts, including a refusal, because it is the network being
// tested and not the credential.
func serverReachable(c commonFlags, store provision.Store) bool {
	endpoint := provision.DefaultEndpoint
	if cred, err := store.LoadCredential(); err == nil {
		endpoint = c.endpointFor(cred)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	return true
}
