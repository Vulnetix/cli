package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// The sensor keeps itself current. The guard (root, once a minute) calls
// maybeSelfUpdate; at most every updateEvery it asks GitHub which release is
// latest, and when that is newer than the running binary it downloads the
// sensor for this architecture, checks it against the release's checksums.txt,
// runs it once to prove it starts, swaps it in with a rename and signals the
// service, which exits and is restarted by systemd on the new binary. Nothing
// here needs a person.
//
// A profile can opt out with config autoUpdate=false (a pinned fleet).

const (
	updateEvery   = 6 * time.Hour
	releaseBase   = "https://github.com/Vulnetix/cli/releases"
	updateStamp   = "update.json"
	updateMaxSize = 200 << 20
)

// releaseBaseURL and httpDo are replaced in tests.
var (
	releaseBaseURL = releaseBase
	updateClient   = &http.Client{Timeout: 5 * time.Minute}
)

type updateState struct {
	CheckedAt time.Time `json:"checkedAt"`
	Latest    string    `json:"latest,omitempty"`
	Failed    string    `json:"failed,omitempty"`
}

// parseVersion reads vX.Y.Z (a pre-release or build suffix is ignored, and
// makes the version older than the plain one).
func parseVersion(v string) (nums [3]int, pre bool, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "+"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "-"); i >= 0 {
		pre = true
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nums, false, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nums, false, false
		}
		nums[i] = n
	}

	return nums, pre, true
}

// newerVersion reports whether latest is a stable release newer than current.
// A development or unparseable current is never replaced.
func newerVersion(current, latest string) bool {
	c, _, cok := parseVersion(current)
	l, lpre, lok := parseVersion(latest)
	if !cok || !lok || lpre {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}

	return false
}

// latestTag follows the /releases/latest redirect, which has no API rate
// limit, and returns the tag it lands on.
func latestTag(ctx context.Context) (string, error) {
	cl := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, releaseBaseURL+"/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("latest release: no tag in redirect (status %d)", resp.StatusCode)
	}

	return loc[i+len("/tag/"):], nil
}

func fetch(ctx context.Context, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := updateClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, updateMaxSize+1))
	if err != nil {
		return err
	}
	if n > updateMaxSize {
		return errors.New("download too large")
	}

	return nil
}

// downloadRelease fetches the sensor for tag into dir and returns its path,
// only when its SHA-256 matches the release's checksums.txt.
func downloadRelease(ctx context.Context, tag, dir string) (string, error) {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("no release for architecture %s", arch)
	}
	name := "vulnetix-sensor-linux-" + arch
	base := releaseBaseURL + "/download/" + tag
	var sums strings.Builder
	if err := fetch(ctx, base+"/checksums.txt", &sums); err != nil {
		return "", err
	}
	want := ""
	for _, line := range strings.Split(sums.String(), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			want = f[0]
		}
	}
	if want == "" {
		return "", fmt.Errorf("%s not in checksums.txt for %s", name, tag)
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	err = fetch(ctx, base+"/"+name, io.MultiWriter(f, h))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("checksum mismatch for %s: refusing to install", name)
	}

	return path, nil
}

// selfTest runs the downloaded binary and checks it reports the tag.
func selfTest(path, tag string) error {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("new binary does not start: %v", err)
	}
	if !strings.Contains(string(out), strings.TrimPrefix(tag, "v")) {
		return fmt.Errorf("new binary reports %q, not %s", strings.TrimSpace(string(out)), tag)
	}

	return nil
}

// swapBinary replaces target with src, keeping the old binary at target.prev
// for a manual rollback. The rename replaces a running binary without "text
// file busy".
func swapBinary(src, target string) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".vulnetix-sensor.*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	in, err := os.Open(src)
	if err != nil {
		_ = tmp.Close()

		return err
	}
	defer func() { _ = in.Close() }()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if old, err := os.ReadFile(target); err == nil {
		_ = os.WriteFile(target+".prev", old, 0o755)
	}

	return os.Rename(tmp.Name(), target)
}

func loadUpdateState(dir string) updateState {
	var s updateState
	if b, err := os.ReadFile(filepath.Join(dir, updateStamp)); err == nil {
		_ = json.Unmarshal(b, &s)
	}

	return s
}

func saveUpdateState(dir string, s updateState) {
	if b, err := json.Marshal(s); err == nil {
		_ = os.WriteFile(filepath.Join(dir, updateStamp), b, 0o600)
	}
}

// maybeSelfUpdate is the guard's update step. It reports whether it replaced
// the binary (the caller signals the service). enabled is the profile's
// autoUpdate; target is the installed binary; stateDir holds the stamp.
func maybeSelfUpdate(ctx context.Context, enabled bool, current, target, stateDir string, now time.Time) (string, error) {
	if !enabled {
		return "", nil
	}
	if _, _, ok := parseVersion(current); !ok {
		return "", nil // a development build is never replaced
	}
	st := loadUpdateState(stateDir)
	if !st.CheckedAt.IsZero() && now.Sub(st.CheckedAt) < updateEvery {
		return "", nil
	}
	st.CheckedAt = now
	st.Failed = ""
	defer func() { saveUpdateState(stateDir, st) }()

	tag, err := latestTag(ctx)
	if err != nil {
		st.Failed = err.Error()

		return "", err
	}
	st.Latest = tag
	if !newerVersion(current, tag) {
		return "", nil
	}
	dir, err := os.MkdirTemp(filepath.Dir(target), ".vulnetix-update.*")
	if err != nil {
		st.Failed = err.Error()

		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path, err := downloadRelease(ctx, tag, dir)
	if err == nil {
		err = selfTest(path, tag)
	}
	if err == nil {
		err = swapBinary(path, target)
	}
	if err != nil {
		st.Failed = err.Error()

		return "", err
	}

	return tag, nil
}
