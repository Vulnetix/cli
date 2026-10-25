package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCache(t *testing.T) *DiskCache {
	t.Helper()
	dir := t.TempDir()
	return &DiskCache{dir: dir}
}

func TestCacheKey(t *testing.T) {
	k1 := CacheKey("/v1", "/ecosystems")
	k2 := CacheKey("/v1", "/sources")
	k3 := CacheKey("/v1", "/ecosystems")

	if k1 == k2 {
		t.Fatal("different paths should produce different keys")
	}
	if k1 != k3 {
		t.Fatal("same inputs should produce the same key")
	}
	if len(k1) != 64 { // SHA-256 hex = 64 chars
		t.Fatalf("expected 64-char hex key, got %d chars", len(k1))
	}
}

func TestPutAndGetFresh(t *testing.T) {
	c := testCache(t)
	key := CacheKey("/v1", "/ecosystems")

	entry := &Entry{
		Body:     []byte(`{"ecosystems":[]}`),
		ETag:     `"abc123"`,
		CachedAt: time.Now(),
		TTL:      1 * time.Hour,
	}

	if err := c.Put(key, entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got.Body) != string(entry.Body) {
		t.Fatalf("body mismatch: %s", got.Body)
	}
	if got.ETag != entry.ETag {
		t.Fatalf("etag mismatch: %s", got.ETag)
	}
	if !got.IsFresh() {
		t.Fatal("entry should be fresh")
	}
}

func TestGetMiss(t *testing.T) {
	c := testCache(t)
	_, ok := c.Get("nonexistent")
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestStaleEntry(t *testing.T) {
	c := testCache(t)
	key := CacheKey("/v1", "/sources")

	entry := &Entry{
		Body:     []byte(`{"sources":[]}`),
		CachedAt: time.Now().Add(-2 * time.Hour),
		TTL:      1 * time.Hour,
	}

	if err := c.Put(key, entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("stale entry should still be returned")
	}
	if got.IsFresh() {
		t.Fatal("entry should be stale")
	}
}

func TestCorruptedEntry(t *testing.T) {
	c := testCache(t)
	key := "corrupt"
	path := filepath.Join(c.dir, key+".json")

	if err := os.WriteFile(path, []byte("not json{{{"), 0600); err != nil {
		t.Fatal(err)
	}

	_, ok := c.Get(key)
	if ok {
		t.Fatal("corrupted entry should be a miss")
	}

	// File should have been cleaned up
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("corrupted file should be deleted")
	}
}

func TestClear(t *testing.T) {
	c := testCache(t)
	key := CacheKey("/v1", "/test")

	if err := c.Put(key, &Entry{Body: []byte("x"), CachedAt: time.Now(), TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}

	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	_, ok := c.Get(key)
	if ok {
		t.Fatal("expected miss after clear")
	}

	// Dir should still exist after clear
	if _, err := os.Stat(c.dir); err != nil {
		t.Fatalf("cache dir should exist after clear: %v", err)
	}
}

func TestOverwrite(t *testing.T) {
	c := testCache(t)
	key := CacheKey("/v1", "/overwrite")

	e1 := &Entry{Body: []byte("first"), CachedAt: time.Now(), TTL: time.Hour}
	e2 := &Entry{Body: []byte("second"), CachedAt: time.Now(), TTL: time.Hour}

	if err := c.Put(key, e1); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(key, e2); err != nil {
		t.Fatal(err)
	}

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if string(got.Body) != "second" {
		t.Fatalf("expected overwritten value, got %s", got.Body)
	}
}

func TestCacheVersionDir(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.8.3", "v1.8"},
		{"v2.0.0", "v2.0"},
		{"1.8.3-dev", "v1.8"},
		{"0.1.0-rc1", "v0.1"},
		{"3.0.0", "v3.0"},
	}
	for _, tt := range tests {
		if got := cacheVersionDir(tt.in); got != tt.want {
			t.Errorf("cacheVersionDir(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCleanOldCachesRemovesOtherVersions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	baseDir := filepath.Join(home, ".vulnetix", "cache", "vdb")
	for _, name := range []string{"v1.7", "v1.8", "v1.9"} {
		if err := os.MkdirAll(filepath.Join(baseDir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(baseDir, "abc123.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "other"), 0700); err != nil {
		t.Fatal(err)
	}

	removed, err := CleanOldCaches("1.8.5")
	if err != nil {
		t.Fatalf("CleanOldCaches: %v", err)
	}
	if removed != 3 { // v1.7, v1.9, abc123.json
		t.Fatalf("expected 3 removals, got %d", removed)
	}

	for _, name := range []string{"v1.8", "other"} {
		if _, err := os.Stat(filepath.Join(baseDir, name)); err != nil {
			t.Fatalf("%s should survive cleanup: %v", name, err)
		}
	}
	for _, name := range []string{"v1.7", "v1.9", "abc123.json"} {
		if _, err := os.Stat(filepath.Join(baseDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should be removed", name)
		}
	}
}

func TestCleanOldCachesAbsentBaseDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	removed, err := CleanOldCaches("1.8.5")
	if err != nil {
		t.Fatalf("CleanOldCaches: %v", err)
	}
	if removed != 0 {
		t.Fatalf("expected 0 removals, got %d", removed)
	}
}

func TestNewDiskCacheDirLayout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	c, err := NewDiskCache("1.8.5")
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	want := filepath.Join(home, ".vulnetix", "cache", "vdb", "v1.8")
	if got := c.Dir(); got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("cache dir should exist: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Fatalf("cache dir mode = %o, want 0700", perm)
	}

	baseDir, err := CacheBaseDir()
	if err != nil {
		t.Fatalf("CacheBaseDir: %v", err)
	}
	if want := filepath.Join(home, ".vulnetix", "cache", "vdb"); baseDir != want {
		t.Fatalf("CacheBaseDir() = %q, want %q", baseDir, want)
	}
}

func TestNewDiskCacheAt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "custom", "cache")
	c, err := NewDiskCacheAt(dir)
	if err != nil {
		t.Fatalf("NewDiskCacheAt: %v", err)
	}
	if got := c.Dir(); got != dir {
		t.Fatalf("Dir() = %q, want %q", got, dir)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cache dir should exist: %v", err)
	}
}

func TestCacheVersionDirEdges(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1", "v1"},
		{"1.8", "v1.8"},
		{"v", "v"},
		{"", "v"},
	}
	for _, tt := range tests {
		if got := cacheVersionDir(tt.in); got != tt.want {
			t.Errorf("cacheVersionDir(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDir(t *testing.T) {
	dir := t.TempDir()
	c := &DiskCache{dir: dir}
	if got := c.Dir(); got != dir {
		t.Fatalf("Dir() = %q, want %q", got, dir)
	}
}
