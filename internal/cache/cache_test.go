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

	c.Put(key, e1)
	c.Put(key, e2)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if string(got.Body) != "second" {
		t.Fatalf("expected overwritten value, got %s", got.Body)
	}
}
