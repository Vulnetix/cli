// Package filecache holds the on-disk caches that let a scan skip work on files
// whose text has not changed: the SAST result cache and the graph facts cache.
//
// A cache is one JSON document per scanned directory and key, at
// <dir>/<sha256(root)[:16]>/<key>.json. The key names everything the cached
// results depend on besides the files themselves (the CLI build, the rules);
// each entry inside names the file text it was computed from. The caches are a
// convenience: a document that cannot be read is empty, and one that cannot be
// written is skipped, never an error.
package filecache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Keep is how many documents (keys) are kept per scanned directory; older ones
// are removed when a new one is written. Each rule set is its own key, and
// scan, sast, secrets, iac and containers each evaluate a different one, so
// fewer than five meant running them in turn over one tree evicted every
// cache before it was read again.
const Keep = 8

// Path is the document for the scan root and key under dir.
func Path(dir, root, key string) string {
	rootSum := sha256.Sum256([]byte(root))
	return filepath.Join(dir, hex.EncodeToString(rootSum[:])[:16], key+".json")
}

// ContentSHA is the hex SHA-256 of a file's text, the identity an entry is
// checked against.
func ContentSHA(text []byte) string {
	sum := sha256.Sum256(text)
	return hex.EncodeToString(sum[:])
}

// Write replaces the document at path atomically, then removes that
// directory's documents beyond the newest Keep. It reports nothing: a cache
// that could not be written is a slower next run, not a failed one.
func Write(path string, data []byte) {
	dir := filepath.Dir(path)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".write-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), path) != nil {
		os.Remove(tmp.Name())
		return
	}
	Prune(dir, Keep)
}

// Prune keeps the newest keep documents in dir.
func Prune(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type aged struct {
		name string
		mod  time.Time
	}
	var all []aged
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if info, err := e.Info(); err == nil {
			all = append(all, aged{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod.After(all[j].mod) })
	for i := keep; i < len(all); i++ {
		os.Remove(filepath.Join(dir, all[i].name))
	}
}
