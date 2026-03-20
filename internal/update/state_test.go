package update

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestShouldCheckForUpdate_MissingFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if !ShouldCheckForUpdate() {
		t.Fatal("expected true when state file does not exist")
	}
}

func TestShouldCheckForUpdate_StaleTimestamp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".vulnetix", "state")
	os.MkdirAll(dir, 0700)

	stale := time.Now().Add(-25 * time.Hour).Unix()
	os.WriteFile(filepath.Join(dir, "last-update-check"), []byte(strconv.FormatInt(stale, 10)), 0600)

	if !ShouldCheckForUpdate() {
		t.Fatal("expected true when timestamp is >24h old")
	}
}

func TestShouldCheckForUpdate_FreshTimestamp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".vulnetix", "state")
	os.MkdirAll(dir, 0700)

	fresh := time.Now().Add(-1 * time.Hour).Unix()
	os.WriteFile(filepath.Join(dir, "last-update-check"), []byte(strconv.FormatInt(fresh, 10)), 0600)

	if ShouldCheckForUpdate() {
		t.Fatal("expected false when timestamp is <24h old")
	}
}

func TestRecordUpdateCheck(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	RecordUpdateCheck()

	data, err := os.ReadFile(filepath.Join(home, ".vulnetix", "state", "last-update-check"))
	if err != nil {
		t.Fatalf("state file should exist after RecordUpdateCheck: %v", err)
	}
	ts, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		t.Fatalf("state file should contain a unix timestamp: %v", err)
	}
	if time.Since(time.Unix(ts, 0)) > 5*time.Second {
		t.Fatal("recorded timestamp should be recent")
	}
}
