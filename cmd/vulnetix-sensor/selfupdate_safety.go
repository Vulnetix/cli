package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vulnetix/cli/v4/internal/sensor/provision"
)

// failureBackoff is how long the guard waits after a failed update check
// before it tries again: 10 minutes, then 30, then 2 hours, then the usual
// six. A success goes back to updateEvery.
func failureBackoff(failures int) time.Duration {
	steps := []time.Duration{10 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	if failures >= 1 && failures <= len(steps) {
		return steps[failures-1]
	}

	return updateEvery
}

// staleUpdateAge is how old a leftover download or swap file must be before
// the guard removes it: a guard killed mid-update leaves one behind.
const staleUpdateAge = time.Hour

// sweepStaleUpdates removes leftover .vulnetix-update.* directories and
// .vulnetix-sensor.* temporary binaries older than staleUpdateAge from dir.
func sweepStaleUpdates(dir string, now time.Time) int {
	removed := 0
	for _, pattern := range []string{".vulnetix-update.*", ".vulnetix-sensor.*"} {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, m := range matches {
			info, err := os.Lstat(m)
			if err != nil || now.Sub(info.ModTime()) < staleUpdateAge {
				continue
			}
			if os.RemoveAll(m) == nil {
				removed++
			}
		}
	}

	return removed
}

// updateBase is where releases are fetched from: the profile's https mirror
// when it names a valid one, else GitHub.
func updateBase(cfg provision.Config) string {
	raw := strings.TrimSpace(cfg.UpdateBaseURL)
	if raw == "" {
		return releaseBase
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		fmt.Fprintf(os.Stderr, "guard: updateBaseUrl %q is not an https URL; using GitHub\n", raw)

		return releaseBase
	}

	return strings.TrimRight(u.String(), "/")
}

// releaseSigningKey is the base64 Ed25519 public key that signs a release's
// checksums.txt (checksums.txt.sig). Empty until the release signing secret
// exists; once set, an update without a valid signature is refused. Set at
// build time with -ldflags "-X main.releaseSigningKey=<base64>".
var releaseSigningKey = ""

// verifyChecksums checks sums against checksums.txt.sig when a signing key is
// pinned. Without a pin it accepts the checksums as before.
func verifyChecksums(ctx context.Context, base, tag string, sums []byte) error {
	if releaseSigningKey == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(releaseSigningKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("the pinned release signing key is malformed")
	}
	var sig strings.Builder
	if err := fetch(ctx, base+"/download/"+tag+"/checksums.txt.sig", &sig); err != nil {
		return fmt.Errorf("release %s has no checksums signature: %w", tag, err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.String()))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), sums, raw) {
		return fmt.Errorf("release %s: checksums.txt signature does not verify: refusing to install", tag)
	}

	return nil
}

// updateSkipReason says why the guard must not replace the binary at all: the
// running sensor is not the unit's binary (a copy run by hand, or a package
// manager's), or that binary cannot be replaced. Units are never repointed.
func updateSkipReason(running, unitBin string) string {
	if r, err := filepath.EvalSymlinks(running); err == nil {
		running = r
	}
	target := unitBin
	if r, err := filepath.EvalSymlinks(unitBin); err == nil {
		target = r
	}
	if running != target {
		return fmt.Sprintf("the guard runs %s, not the unit's %s", running, unitBin)
	}
	if err := unix.Access(filepath.Dir(unitBin), unix.W_OK); err != nil {
		return fmt.Sprintf("%s is not writable: %v", filepath.Dir(unitBin), err)
	}

	return ""
}

// selfcheckCmd checks that this binary can run on the installed config: the
// credential is there and the profile snapshot parses. A release that cannot
// is not swapped in. It contacts nothing.
func selfcheckCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor selfcheck", flag.ContinueOnError)
	c := defineCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := c.store()
	if !store.HasCredential() {
		fmt.Println("selfcheck: not enrolled")

		return nil
	}
	if _, err := store.LoadCredential(); err != nil {
		return fmt.Errorf("selfcheck: credential: %w", err)
	}
	snap, _, err := provision.LoadSnapshot(snapshotPaths(store, *c.stateDir)...)
	if err != nil {
		return fmt.Errorf("selfcheck: profile config: %w", err)
	}
	fmt.Printf("selfcheck: ok (profile %s, protection %s)\n", snap.Profile.Name, snap.Config.Level())

	return nil
}

// lastUpdateOutcome is the guard's last recorded update outcome as JSON, for
// the sensor's register. The guard writes update.json readable by the sensor.
func lastUpdateOutcome(stateDir string) json.RawMessage {
	st := loadUpdateState(stateDir)
	if st.Outcome == nil {
		return nil
	}
	b, err := json.Marshal(st.Outcome)
	if err != nil {
		return nil
	}

	return b
}

// selfcheckArgs is what selfTest runs the new binary with after --version; the
// guard sets the directories it was started with.
var selfcheckArgs = []string{"selfcheck"}
