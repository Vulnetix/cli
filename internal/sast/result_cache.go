package sast

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"

	"github.com/vulnetix/cli/v3/internal/filecache"
)

// Result cache: the findings of rules whose input has not changed since an
// earlier run of the same rules.
//
// Two kinds of entry are kept. A file entry holds the findings of the per-file
// rules (moduleReach.perFile without usesTree) for one file, and is a hit when
// the path and the SHA-256 of its text match. A group entry holds the findings
// of every other rule in one scope group, and is a hit when nothing those
// rules read has changed: the file list, the language directories, the scan
// root and the text of every file in the group's scope. Rules that call a
// volatile builtin (the clock, the network, a random number) are never cached.
//
// The key covers every module evaluated and the CLI build, so an edited rule,
// an added pack, a language newly present in the project or a new binary is a
// different cache. The doc also holds every rule's metadata, so a run that
// evaluates nothing compiles nothing. Findings are stored after the engine's
// scope check and before nosec, suppressions and org policy, which run on
// every scan as before.
//
// The cache is a convenience: a file that cannot be read or written is
// treated as empty, never as an error, and a run whose per-file findings
// cannot all be attributed to the file they came from writes nothing.
const resultCacheVersion = 2

type cachedFile struct {
	SHA      string    `json:"sha"`
	Findings []Finding `json:"findings"`
}

type cachedGroup struct {
	Key      string    `json:"key"`
	Findings []Finding `json:"findings"`
}

type resultCacheDoc struct {
	Version int                    `json:"version"`
	Rules   []RuleMetadata         `json:"rules"`
	Files   map[string]cachedFile  `json:"files"`
	Groups  map[string]cachedGroup `json:"groups"`
}

type resultCache struct {
	path string
	// rules is every rule's metadata, nil when no usable cache was read; a
	// cache without it serves nothing.
	rules  []RuleMetadata
	files  map[string]cachedFile
	groups map[string]cachedGroup
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
	c := &resultCache{
		path:   filecache.Path(dir, root, key),
		files:  map[string]cachedFile{},
		groups: map[string]cachedGroup{},
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return c
	}
	var doc resultCacheDoc
	if json.Unmarshal(data, &doc) != nil || doc.Version != resultCacheVersion || doc.Rules == nil {
		return c
	}
	c.rules = doc.Rules
	if doc.Files != nil {
		c.files = doc.Files
	}
	if doc.Groups != nil {
		c.groups = doc.Groups
	}
	return c
}

func contentSHA(text string) string {
	return filecache.ContentSHA([]byte(text))
}

// lookup returns the cached findings for path when its text is unchanged.
func (c *resultCache) lookup(path, sha string) ([]Finding, bool) {
	if c.rules == nil {
		return nil, false
	}
	e, ok := c.files[path]
	if !ok || e.SHA != sha {
		return nil, false
	}
	return e.Findings, true
}

// lookupGroup returns the cached findings of a scope group's uncacheable-per-
// file rules when nothing they read has changed.
func (c *resultCache) lookupGroup(scope, key string) ([]Finding, bool) {
	if c.rules == nil {
		return nil, false
	}
	e, ok := c.groups[scope]
	if !ok || e.Key != key {
		return nil, false
	}
	return e.Findings, true
}

// save replaces the cache, then removes this directory's caches beyond the
// newest resultCacheKeep. Errors are dropped: the cache is an optimisation.
func (c *resultCache) save(doc resultCacheDoc) {
	doc.Version = resultCacheVersion
	if doc.Rules == nil {
		doc.Rules = []RuleMetadata{}
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return
	}
	filecache.Write(c.path, data)
}

// cacheRun is one evaluation's use of the cache: the files and groups it
// served and those it sent to be evaluated. A nil *cacheRun is a run without
// a cache.
type cacheRun struct {
	store  *resultCache
	in     *ScanInput
	sha    map[string]string
	hits   map[string][]Finding
	misses map[string]bool

	groupHits   map[string][]Finding
	groupMisses map[string]string // scope key → group key
	treeSum     string
}

func newCacheRun(opts EvalOptions, in *ScanInput, modules map[string]string) *cacheRun {
	if opts.CacheDir == "" {
		return nil
	}
	return &cacheRun{
		store:       openResultCache(opts.CacheDir, in.ScanRoot, resultCacheKey(opts.CacheSalt, modules)),
		in:          in,
		sha:         map[string]string{},
		hits:        map[string][]Finding{},
		misses:      map[string]bool{},
		groupHits:   map[string][]Finding{},
		groupMisses: map[string]string{},
	}
}

// rules is every rule's metadata from the cache, or nil when the run has to
// read it from evaluation.
func (c *cacheRun) rules() []RuleMetadata {
	if c == nil {
		return nil
	}
	return c.store.rules
}

func (c *cacheRun) shaOf(path string) string {
	sum, ok := c.sha[path]
	if !ok {
		sum = contentSHA(c.in.FileContents[path])
		c.sha[path] = sum
	}
	return sum
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
		if fs, ok := c.store.lookup(p, c.shaOf(p)); ok {
			c.hits[p] = fs
		} else {
			c.misses[p] = true
			out = append(out, p)
		}
	}
	return out
}

// tree is a digest of the input every group shares: the scan root, the file
// list and the language directories.
func (c *cacheRun) tree() string {
	if c.treeSum != "" {
		return c.treeSum
	}
	h := sha256.New()
	h.Write([]byte(c.in.ScanRoot))
	h.Write([]byte{0})
	paths := make([]string, 0, len(c.in.FileSet))
	for p := range c.in.FileSet {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	h.Write([]byte{1})
	langs := make([]string, 0, len(c.in.DirsByLanguage))
	for l := range c.in.DirsByLanguage {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	for _, l := range langs {
		h.Write([]byte(l))
		h.Write([]byte{0})
		for _, d := range c.in.DirsByLanguage[l] {
			h.Write([]byte(d))
			h.Write([]byte{0})
		}
		h.Write([]byte{1})
	}
	c.treeSum = hex.EncodeToString(h.Sum(nil))
	return c.treeSum
}

// group looks up a scope group's uncacheable-per-file rules: in is the group's
// scoped input. On a hit it returns true and the run serves the findings; on a
// miss the caller evaluates the rules and finish stores what they found.
func (c *cacheRun) group(scope string, in *ScanInput) bool {
	h := sha256.New()
	h.Write([]byte(c.tree()))
	for _, p := range inputPaths(in) {
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write([]byte(c.shaOf(p)))
	}
	key := hex.EncodeToString(h.Sum(nil))
	if fs, ok := c.store.lookupGroup(scope, key); ok {
		c.groupHits[scope] = fs
		return true
	}
	c.groupMisses[scope] = key
	return false
}

// finish returns the cached findings the run served, linked to rules, and
// writes the cache for the next run. reports[i] is units[i]'s.
func (c *cacheRun) finish(units []*evalUnit, reports []*SASTReport, rules []RuleMetadata) []Finding {
	if c == nil {
		return nil
	}
	meta := make(map[string]*RuleMetadata, len(rules))
	for i := range rules {
		meta[rules[i].ID] = &rules[i]
	}
	doc := resultCacheDoc{Rules: rules, Files: map[string]cachedFile{}, Groups: map[string]cachedGroup{}}
	attributable := true
	for i, u := range units {
		rep := reports[i]
		switch {
		case u.cacheable:
			for _, f := range rep.Findings {
				if !c.misses[f.ArtifactURI] {
					// A finding on a file the batch did not hold cannot be
					// stored against the file that produced it.
					attributable = false
					continue
				}
				e := doc.Files[f.ArtifactURI]
				e.Findings = append(e.Findings, f)
				doc.Files[f.ArtifactURI] = e
			}
		case u.group != "":
			e := doc.Groups[u.group]
			e.Key = c.groupMisses[u.group]
			e.Findings = append(e.Findings, rep.Findings...)
			doc.Groups[u.group] = e
		}
	}
	for p := range c.misses {
		e := doc.Files[p]
		e.SHA = c.sha[p]
		doc.Files[p] = e
	}
	for scope, key := range c.groupMisses {
		if _, ok := doc.Groups[scope]; !ok {
			doc.Groups[scope] = cachedGroup{Key: key}
		}
	}
	var out []Finding
	served := func(fs []Finding) {
		for _, f := range fs {
			f.Fingerprint = Fingerprint(f.RuleID, f.ArtifactURI, f.StartLine)
			f.Metadata = meta[f.RuleID]
			out = append(out, f)
		}
	}
	for p, fs := range c.hits {
		doc.Files[p] = cachedFile{SHA: c.sha[p], Findings: fs}
		served(fs)
	}
	for scope, fs := range c.groupHits {
		doc.Groups[scope] = c.store.groups[scope]
		served(fs)
	}
	if attributable {
		c.store.save(doc)
	}
	return out
}

// counts is how many files and scope groups the run served from the cache
// and evaluated.
func (c *cacheRun) counts() (hits, evaluated, groupHits, groupsEvaluated int) {
	if c == nil {
		return 0, 0, 0, 0
	}
	return len(c.hits), len(c.misses), len(c.groupHits), len(c.groupMisses)
}
