package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/provision"
)

func TestFailureBackoffGrowsToTheUsualInterval(t *testing.T) {
	want := []time.Duration{updateEvery, 10 * time.Minute, 30 * time.Minute, 2 * time.Hour, updateEvery, updateEvery}
	for n, w := range want {
		if got := failureBackoff(n); got != w {
			t.Errorf("failureBackoff(%d) = %v, want %v", n, got, w)
		}
	}
}

func TestSweepStaleUpdatesRemovesOnlyOldLeftovers(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for _, name := range []string{".vulnetix-update.old", ".vulnetix-sensor.old", ".vulnetix-update.new", "vulnetix-sensor"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, ".old") {
			_ = os.Chtimes(p, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
		}
	}
	if n := sweepStaleUpdates(dir, now); n != 2 {
		t.Fatalf("removed %d, want the two old leftovers", n)
	}
	for _, keep := range []string{".vulnetix-update.new", "vulnetix-sensor"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s was removed", keep)
		}
	}
}

func TestUpdateBaseTakesOnlyAnHTTPSMirror(t *testing.T) {
	for raw, want := range map[string]string{
		"":                                     releaseBase,
		"https://mirror.example/vulnetix/cli/": "https://mirror.example/vulnetix/cli",
		"http://mirror.example/cli":            releaseBase,
		"https://user:pw@mirror.example/cli":   releaseBase,
		"not a url":                            releaseBase,
	} {
		if got := updateBase(provision.Config{UpdateBaseURL: raw}); got != want {
			t.Errorf("updateBase(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestVerifyChecksumsWithAPinnedKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sums := []byte("abc  vulnetix-sensor-linux-amd64\n")
	good := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums))
	sig := good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sig == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(sig + "\n"))
	}))
	defer srv.Close()
	defer func(k string) { releaseSigningKey = k }(releaseSigningKey)
	ctx := context.Background()

	releaseSigningKey = ""
	if err := verifyChecksums(ctx, srv.URL, "v1.0.0", sums); err != nil {
		t.Fatalf("no pin must accept as before: %v", err)
	}
	releaseSigningKey = base64.StdEncoding.EncodeToString(pub)
	if err := verifyChecksums(ctx, srv.URL, "v1.0.0", sums); err != nil {
		t.Fatalf("a good signature: %v", err)
	}
	if err := verifyChecksums(ctx, srv.URL, "v1.0.0", []byte("tampered")); err == nil {
		t.Fatal("a signature over other checksums must be refused")
	}
	sig = ""
	if err := verifyChecksums(ctx, srv.URL, "v1.0.0", sums); err == nil {
		t.Fatal("a pinned key with no signature must be refused")
	}
}

func TestUpdateSkipReason(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "vulnetix-sensor")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := updateSkipReason(bin, bin); r != "" {
		t.Errorf("the unit's own writable binary: %q", r)
	}
	if r := updateSkipReason(filepath.Join(dir, "other"), bin); !strings.Contains(r, "not the unit") {
		t.Errorf("another binary: %q", r)
	}
}

func TestSelfcheckAcceptsAnEnrolledConfig(t *testing.T) {
	dir := t.TempDir()
	if err := selfcheckCmd([]string{"--config-dir", dir, "--state-dir", dir}); err != nil {
		t.Fatalf("not enrolled is not an error: %v", err)
	}
}
