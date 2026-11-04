//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchPackageDBsReportsAChangeOnceItIsQuiet(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var/lib/pacman/local")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan struct{}, 1)
	go watchPackageDBs(ctx, root, 200*time.Millisecond, changed)
	time.Sleep(300 * time.Millisecond) // the watch is set up

	for i := 0; i < 3; i++ { // one upgrade of several packages
		if err := os.MkdirAll(filepath.Join(dir, "pkg-"+string(rune('a'+i))), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("a package database change was not reported")
	}
	select {
	case <-changed:
		t.Fatal("one burst of changes must be one report")
	case <-time.After(1500 * time.Millisecond):
	}
}

func TestWatchPackageDBsWithNothingToWatchReturns(t *testing.T) {
	done := make(chan struct{})
	go func() {
		watchPackageDBs(context.Background(), t.TempDir(), time.Second, make(chan struct{}, 1))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a host with no package database must not keep a watcher")
	}
}
