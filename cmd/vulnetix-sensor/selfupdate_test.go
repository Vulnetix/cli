package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"v3.158.0", "v3.164.0", true},
		{"v3.164.0", "v3.164.0", false},
		{"v3.164.1", "v3.164.0", false},
		{"v3.9.0", "v3.10.0", true},
		{"dev", "v3.164.0", false},
		{"v3.158.0", "v3.165.0-rc.1", false},
		{"v3.158.0", "garbage", false},
	}
	for _, c := range cases {
		if got := newerVersion(c.cur, c.latest); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.cur, c.latest, got, c.want)
		}
	}
}

// fakeRelease serves /latest as a redirect to /tag/<tag> and a "sensor"
// script that prints the tag, with a checksums.txt that is correct unless bad.
func fakeRelease(t *testing.T, tag string, bad bool) *httptest.Server {
	t.Helper()
	name := "vulnetix-sensor-linux-" + runtime.GOARCH
	body := "#!/bin/sh\necho vulnetix-sensor " + tag + "\n"
	sum := sha256.Sum256([]byte(body))
	hexsum := hex.EncodeToString(sum[:])
	if bad {
		hexsum = hex.EncodeToString(make([]byte, 32))
	}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/download/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hexsum, name)
	})
	mux.HandleFunc("/download/"+tag+"/"+name, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func TestSelfUpdateReplacesTheBinary(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir := t.TempDir()
	target := filepath.Join(dir, "vulnetix-sensor")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now)
	if err != nil || tag != "v3.200.0" {
		t.Fatalf("tag %q err %v", tag, err)
	}
	if b, _ := os.ReadFile(target); string(b) == "old" {
		t.Fatal("binary was not replaced")
	}
	if b, _ := os.ReadFile(target + ".prev"); string(b) != "old" {
		t.Fatal("previous binary was not kept for rollback")
	}
	// Checked just now: the next call within the interval does nothing.
	if tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, now.Add(time.Hour)); tag != "" || err != nil {
		t.Fatalf("rechecked inside the interval: %q %v", tag, err)
	}
}

func TestSelfUpdateRefusesABadChecksum(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", true)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir := t.TempDir()
	target := filepath.Join(dir, "vulnetix-sensor")
	_ = os.WriteFile(target, []byte("old"), 0o755)
	tag, err := maybeSelfUpdate(context.Background(), true, false, "v3.158.0", target, dir, time.Now())
	if err == nil || tag != "" {
		t.Fatalf("a checksum mismatch installed %q (err %v)", tag, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Fatal("binary changed despite the mismatch")
	}
}

func TestSelfUpdateOffAndDevAndCurrent(t *testing.T) {
	srv := fakeRelease(t, "v3.200.0", false)
	releaseBaseURL = srv.URL
	t.Cleanup(func() { releaseBaseURL = releaseBase })
	dir := t.TempDir()
	target := filepath.Join(dir, "vulnetix-sensor")
	_ = os.WriteFile(target, []byte("old"), 0o755)
	for name, c := range map[string]struct {
		on  bool
		cur string
	}{"opted out": {false, "v3.158.0"}, "dev build": {true, "dev"}, "already current": {true, "v3.200.0"}} {
		if tag, err := maybeSelfUpdate(context.Background(), c.on, false, c.cur, target, dir, time.Now()); tag != "" || err != nil {
			t.Errorf("%s: %q %v", name, tag, err)
		}
		_ = os.Remove(filepath.Join(dir, updateStamp))
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Fatal("binary changed when it should not have")
	}
}
