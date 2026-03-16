package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Entry represents a cached HTTP response.
type Entry struct {
	Body         []byte    `json:"body"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"lastModified,omitempty"`
	CachedAt     time.Time `json:"cachedAt"`
	TTL          time.Duration `json:"ttl"`
}

// IsFresh returns true if the entry has not expired.
func (e *Entry) IsFresh() bool {
	return time.Since(e.CachedAt) < e.TTL
}

// DiskCache stores HTTP responses on disk.
type DiskCache struct {
	dir string
}

// NewDiskCache creates a new disk cache rooted at ~/.vulnetix/cache/vdb.
func NewDiskCache() (*DiskCache, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cache: user home dir: %w", err)
	}
	dir := filepath.Join(homeDir, ".vulnetix", "cache", "vdb")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("cache: mkdir %s: %w", dir, err)
	}
	return &DiskCache{dir: dir}, nil
}

// CacheKey returns a filesystem-safe hex key for an API version + path.
func CacheKey(apiVersion, path string) string {
	h := sha256.Sum256([]byte(apiVersion + path))
	return hex.EncodeToString(h[:])
}

// Get retrieves a cache entry. Returns (entry, true) on hit.
// A stale entry is still returned so callers can do conditional requests.
func (c *DiskCache) Get(key string) (*Entry, bool) {
	data, err := os.ReadFile(filepath.Join(c.dir, key+".json"))
	if err != nil {
		return nil, false
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		// Corrupted — delete and treat as miss
		os.Remove(filepath.Join(c.dir, key+".json"))
		return nil, false
	}
	return &entry, true
}

// Put writes a cache entry to disk atomically.
func (c *DiskCache) Put(key string, entry *Entry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	target := filepath.Join(c.dir, key+".json")

	// Write to temp file in same dir, then rename for atomicity.
	tmp, err := os.CreateTemp(c.dir, "tmp-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	// On Windows os.Rename requires target not to exist.
	os.Remove(target)
	return os.Rename(tmpName, target)
}

// Clear removes all cached entries.
func (c *DiskCache) Clear() error {
	if err := os.RemoveAll(c.dir); err != nil {
		return err
	}
	return os.MkdirAll(c.dir, 0700)
}

// Dir returns the cache directory path.
func (c *DiskCache) Dir() string {
	return c.dir
}
