package analyze

// The graph cache: each file's graph facts and egress sightings, kept between runs so a file
// whose text has not changed is not parsed again.
//
// An entry is the facts computed from one file's text, checked against the SHA-256 of that
// text. Facts are a pure function of the path and text (file_facts.go), so a hit is exactly
// what parsing would produce. The key names the CLI build; a new build is a new cache. Only
// the per-file reading is cached: ids, caps and resolution are recomputed every run by the
// collectors' merge, so the report does not depend on which files were hits.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/vulnetix/cli/v3/internal/filecache"
)

const graphCacheVersion = 1

type cachedFacts struct {
	SHA   string     `json:"sha"`
	Facts *fileFacts `json:"facts"`
}

type cachedEgress struct {
	SHA       string           `json:"sha"`
	Sightings []egressSighting `json:"sightings"`
}

type graphCacheDoc struct {
	Version int                     `json:"version"`
	Files   map[string]cachedFacts  `json:"files"`
	Egress  map[string]cachedEgress `json:"egress"`
}

// graphCache is one run's use of the cache: what the last run left, and what this run will
// leave. A nil *graphCache is a run without one.
type graphCache struct {
	path string
	old  graphCacheDoc

	mu   sync.Mutex
	next graphCacheDoc
}

func openGraphCache(opts Options, root string) *graphCache {
	if opts.CacheDir == "" {
		return nil
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	h := sha256.Sum256([]byte(opts.CacheSalt + "\x00graph\x00" + strconv.Itoa(graphCacheVersion)))
	c := &graphCache{
		path: filecache.Path(opts.CacheDir, root, hex.EncodeToString(h[:])[:24]),
		next: graphCacheDoc{Version: graphCacheVersion, Files: map[string]cachedFacts{}, Egress: map[string]cachedEgress{}},
	}
	if data, err := os.ReadFile(c.path); err == nil {
		var doc graphCacheDoc
		if json.Unmarshal(data, &doc) == nil && doc.Version == graphCacheVersion {
			c.old = doc
		}
	}
	return c
}

// factsFor returns the cached facts for rel when src is the text they were computed from,
// and otherwise computes them with compute. Either way they are kept for the next run.
func (c *graphCache) factsFor(rel string, src []byte, compute func() *fileFacts) *fileFacts {
	if c == nil {
		return compute()
	}
	sha := filecache.ContentSHA(src)
	e, ok := c.old.Files[rel]
	if !ok || e.SHA != sha || e.Facts == nil {
		e = cachedFacts{SHA: sha, Facts: compute()}
	}
	c.mu.Lock()
	c.next.Files[rel] = e
	c.mu.Unlock()
	return e.Facts
}

// egressFor is factsFor for a file's egress sightings.
func (c *graphCache) egressFor(rel string, body []byte, compute func() []egressSighting) []egressSighting {
	if c == nil {
		return compute()
	}
	sha := filecache.ContentSHA(body)
	e, ok := c.old.Egress[rel]
	if !ok || e.SHA != sha {
		e = cachedEgress{SHA: sha, Sightings: compute()}
	}
	c.mu.Lock()
	c.next.Egress[rel] = e
	c.mu.Unlock()
	return e.Sightings
}

// save writes what this run read, so files that were deleted drop out.
func (c *graphCache) save() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.Marshal(c.next)
	if err != nil {
		return
	}
	filecache.Write(c.path, data)
}
