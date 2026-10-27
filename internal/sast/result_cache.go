package sast

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Result cache: the findings of per-file rules for files whose text has not
// changed since an earlier run of the same rules.
//
// Only rules whose findings depend on one file's text and nothing else are
// cached (moduleReach.perFile without usesTree). A file is a hit when its
// path and the SHA-256 of its text match an entry written by a run with the
// same key; the key covers every module evaluated and the CLI build, so an
// edited rule, an added pack, a language newly present in the project or a
// new binary is a different cache. Findings are stored after the engine's
// scope check and before nosec, suppressions and org policy, which run on
// every scan as before.
//
// The cache is a convenience: a file that cannot be read or written is
// treated as empty, never as an error, and a run whose per-file findings
// cannot all be attributed to the file they came from writes nothing.
const resultCacheVersion = 1

// resultCacheKeep is how many caches (rule sets) are kept per scanned
// directory; older ones are removed when a new one is written.
const resultCacheKeep = 3

type cachedFile struct {
	SHA      string    `json:"sha"`
	Findings []Finding `json:"findings"`
}

type resultCacheDoc struct {
	Version int                   `json:"version"`
	Files   map[string]cachedFile `json:"files"`
}

type resultCache struct {
	path  string
	files map[string]cachedFile
}

// resultCacheKey identifies a rule set and build: salt is the CLI build, and
// modules every module the run evaluates.
func resultCacheKey(salt string, modules map[string]string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte{0})
	h.Write([]byte(ModulesDigest(modules)))
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// openResultCache reads the cache for the scan root and key under dir.
func openResultCache(dir, root, key string) *resultCache {
	rootSum := sha256.Sum256([]byte(root))
	c := &resultCache{
		path:  filepath.Join(dir, hex.EncodeToString(rootSum[:])[:16], key+".json"),
		files: map[string]cachedFile{},
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return c
	}
	var doc resultCacheDoc
	if json.Unmarshal(data, &doc) == nil && doc.Version == resultCacheVersion && doc.Files != nil {
		c.files = doc.Files
	}
	return c
}

func contentSHA(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// lookup returns the cached findings for path when its text is unchanged.
func (c *resultCache) lookup(path, sha string) ([]Finding, bool) {
	e, ok := c.files[path]
	if !ok || e.SHA != sha {
		return nil, false
	}
	return e.Findings, true
}

// save replaces the cache with entries, then removes this directory's caches
// beyond the newest resultCacheKeep. Errors are dropped: the cache is an
// optimisation.
func (c *resultCache) save(entries map[string]cachedFile) {
	data, err := json.Marshal(resultCacheDoc{Version: resultCacheVersion, Files: entries})
	if err != nil {
		return
	}
	dir := filepath.Dir(c.path)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".write-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), c.path) != nil {
		os.Remove(tmp.Name())
		return
	}
	pruneResultCaches(dir, resultCacheKeep)
}

// cacheRun is one evaluation's use of the cache: the files it served and the
// files it sent to be evaluated. A nil *cacheRun is a run without a cache.
type cacheRun struct {
	store  *resultCache
	text   map[string]string
	sha    map[string]string
	hits   map[string][]Finding
	misses map[string]bool
}

func newCacheRun(opts EvalOptions, in *ScanInput, modules map[string]string) *cacheRun {
	if opts.CacheDir == "" {
		return nil
	}
	return &cacheRun{
		store:  openResultCache(opts.CacheDir, in.ScanRoot, resultCacheKey(opts.CacheSalt, modules)),
		text:   in.FileContents,
		sha:    map[string]string{},
		hits:   map[string][]Finding{},
		misses: map[string]bool{},
	}
}

// missesOf is the files of in, sorted, that the cache cannot serve. A file in
// several scopes is looked up once.
func (c *cacheRun) missesOf(in *ScanInput) []string {
	var out []string
	for _, p := range inputPaths(in) {
		if c.misses[p] {
			out = append(out, p)
			continue
		}
		if _, hit := c.hits[p]; hit {
			continue
		}
		sum := contentSHA(c.text[p])
		c.sha[p] = sum
		if fs, ok := c.store.lookup(p, sum); ok {
			c.hits[p] = fs
		} else {
			c.misses[p] = true
			out = append(out, p)
		}
	}
	return out
}

// finish returns the cached findings of the files that were hits, linked to
// this run's rule metadata, and writes the cache for the next run. reports[i]
// is units[i]'s.
func (c *cacheRun) finish(units []*evalUnit, reports []*SASTReport) []Finding {
	if c == nil {
		return nil
	}
	meta := map[string]*RuleMetadata{}
	entries := map[string]cachedFile{}
	attributable := true
	for i, u := range units {
		if !u.cacheable {
			continue
		}
		rep := reports[i]
		for j := range rep.Rules {
			meta[rep.Rules[j].ID] = &rep.Rules[j]
		}
		for _, f := range rep.Findings {
			if !c.misses[f.ArtifactURI] {
				// A finding on a file the batch did not hold cannot be
				// stored against the file that produced it.
				attributable = false
				continue
			}
			e := entries[f.ArtifactURI]
			e.Findings = append(e.Findings, f)
			entries[f.ArtifactURI] = e
		}
	}
	for p := range c.misses {
		e := entries[p]
		e.SHA = c.sha[p]
		entries[p] = e
	}
	var out []Finding
	for p, fs := range c.hits {
		entries[p] = cachedFile{SHA: c.sha[p], Findings: fs}
		for _, f := range fs {
			f.Fingerprint = Fingerprint(f.RuleID, f.ArtifactURI, f.StartLine)
			f.Metadata = meta[f.RuleID]
			out = append(out, f)
		}
	}
	if attributable {
		c.store.save(entries)
	}
	return out
}

// counts is how many files the run served from the cache and evaluated.
func (c *cacheRun) counts() (hits, evaluated int) {
	if c == nil {
		return 0, 0
	}
	return len(c.hits), len(c.misses)
}

func pruneResultCaches(dir string, keep int) {
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
