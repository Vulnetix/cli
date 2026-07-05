package aibom

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

func itoa(i int) string { return strconv.Itoa(i) }

// defaultMaxDepth bounds the filesystem walk when the caller does not set one.
// Large enough to reach nested config (e.g. .claude/agents/foo.md) and source
// trees; node_modules/vendor/etc. are still skipped by the sast walker.
const defaultMaxDepth = 64

// maxSourceFileSize caps the size of a file whose contents are scanned for SDK
// usage / model literals (mirrors the SAST content-scan cap).
const maxSourceFileSize = 1 << 20

// maxEvidenceCollect caps how much evidence we retain per detection in memory;
// the BOM builder applies its own (smaller) output cap.
const maxEvidenceCollect = 200

// Options controls a detection run.
type Options struct {
	Root        string
	MaxDepth    int
	Ignore      []string
	ScanEnv     bool
	IncludeHome bool
	ScanSource  bool
	ScanCommits bool
	// CommitMax bounds how many commits the commit-history pass inspects (<=0
	// uses defaultCommitScanMax).
	CommitMax int
	Catalog   *CompiledCatalog
	// Environ is injectable for tests; defaults to os.Environ() when nil.
	Environ []string
	// RespectGitignore prunes .gitignored paths (default off; the aibom command
	// sets it true unless --aibom-include-ignored is passed).
	RespectGitignore bool
}

// Detect runs the enabled passes and returns CycloneDX-ready detections.
func Detect(opts Options) (cdx.AIDetections, error) {
	if opts.Catalog == nil {
		return cdx.AIDetections{}, fmt.Errorf("aibom: nil catalog")
	}
	root := opts.Root
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return cdx.AIDetections{}, err
	}

	c := &collector{
		cat:    opts.Catalog,
		root:   abs,
		tools:  map[string]*toolHit{},
		libs:   map[string]*libHit{},
		models: map[string]*modelHit{},
	}

	depth := opts.MaxDepth
	if depth <= 0 {
		depth = defaultMaxDepth
	}
	input, err := sast.BuildScanInputWithOptions(abs, sast.BuildOptions{
		MaxDepth:         depth,
		IgnoreGlobs:      opts.Ignore,
		IgnoreGit:        true,
		RespectGitignore: opts.RespectGitignore,
	})
	if err != nil {
		return cdx.AIDetections{}, err
	}

	c.detectFiles(input)
	if opts.ScanEnv {
		env := opts.Environ
		if env == nil {
			env = os.Environ()
		}
		c.detectEnv(env)
	}
	if opts.IncludeHome {
		c.detectHome()
	}
	if opts.ScanSource {
		c.detectSource(input)
	}
	if opts.ScanCommits {
		c.detectCommits(abs, opts.CommitMax)
	}

	return c.result(), nil
}

// ---- collector -----------------------------------------------------------

type collector struct {
	cat    *CompiledCatalog
	root   string
	tools  map[string]*toolHit
	libs   map[string]*libHit
	models map[string]*modelHit
}

type toolHit struct {
	def      ToolDef
	evidence []cdx.AIEvidence
	counts   map[string]int
	methods  map[string]bool
	// primary counts tool-specific file hits; shared counts hits on cross-tool
	// convention files (AGENTS.md, .mcp.json, ...). A tool needs a primary hit
	// (or env/home evidence) to be reported, so a single shared file does not
	// light up every catalog entry that happens to list it.
	primary int
	shared  int
}

// sharedConventionBasenames are instruction/config files used across many tools.
// Matching one of these alone is not enough to attribute a specific tool — it is
// only ever surfaced through a dedicated type:"convention" catalog entry.
var sharedConventionBasenames = map[string]bool{
	"agents.md": true, "agent.md": true, ".rules": true,
	".mcp.json": true, "mcp.json": true,
}

type libHit struct {
	def      LibraryDef
	evidence []cdx.AIEvidence
}

type modelHit struct {
	name          string
	provider      string
	family        string
	viaSDK        string
	viaSDKMatched bool
	task          string
	known         bool
	occur         int
	evidence      []cdx.AIEvidence
	seenLoc       map[string]bool
}

func (c *collector) tool(def ToolDef) *toolHit {
	h := c.tools[def.ID]
	if h == nil {
		h = &toolHit{def: def, counts: map[string]int{}, methods: map[string]bool{}}
		c.tools[def.ID] = h
	}
	return h
}

func (c *collector) addModel(name, sdkProvider, viaSDK, task string, ev cdx.AIEvidence) {
	name = strings.TrimSpace(name)
	if !plausibleModel(name) {
		return
	}
	key := strings.ToLower(name)
	h := c.models[key]
	if h == nil {
		prov, fam, known := c.cat.classifyModel(name, sdkProvider)
		h = &modelHit{name: name, provider: prov, family: fam, task: task, known: known, seenLoc: map[string]bool{}}
		c.models[key] = h
	}
	// Prefer a via-SDK whose provider matches the model's classified provider, so
	// a generic `model=` form in a multi-SDK file is attributed to the right SDK.
	if viaSDK != "" && (h.viaSDK == "" || (!h.viaSDKMatched && sdkProvider != "" && sdkProvider == h.provider)) {
		h.viaSDK = viaSDK
		h.viaSDKMatched = sdkProvider == h.provider
	}
	if h.task == "" {
		h.task = task
	}
	// Dedup by source location so a line matched by two SDKs' extractors counts once.
	if ev.Locator != "" {
		if h.seenLoc[ev.Locator] {
			return
		}
		h.seenLoc[ev.Locator] = true
	}
	h.occur++
	if len(h.evidence) < maxEvidenceCollect {
		h.evidence = append(h.evidence, ev)
	}
}

// ---- result assembly -----------------------------------------------------

// strongCategories are on-disk artifacts that, when present, make a tool
// detection high-confidence (vs. a bare config dir or an ambient env var).
var strongCategories = map[string]bool{
	"instructions": true, "agents": true, "commands": true, "skills": true,
	"hooks": true, "plugins": true, "steering": true, "marketplace": true,
	"prompts": true, "memory": true, "commits": true,
}

func (c *collector) result() cdx.AIDetections {
	out := cdx.AIDetections{CatalogVersion: c.cat.Version}

	toolIDs := make([]string, 0, len(c.tools))
	for id := range c.tools {
		toolIDs = append(toolIDs, id)
	}
	sort.Strings(toolIDs)
	for _, id := range toolIDs {
		h := c.tools[id]
		// Drop tools whose only evidence is a shared convention file (e.g. a bare
		// AGENTS.md). Service (env-based) and convention entries are exempt.
		if h.primary == 0 && !h.methods["env"] && !h.methods["home"] &&
			h.def.Type != "service" && h.def.Type != "convention" {
			continue
		}
		counts := map[string]int{}
		for k, v := range h.counts {
			if k == "env" {
				continue
			}
			counts[k] = v
		}
		out.Tools = append(out.Tools, cdx.AITool{
			ID: h.def.ID, Name: h.def.Name, Vendor: h.def.Vendor, Type: h.def.Type,
			Homepage: h.def.Homepage, Confidence: toolConfidence(h),
			ArtifactCounts: counts, Evidence: h.evidence,
		})
	}

	libIDs := make([]string, 0, len(c.libs))
	for id := range c.libs {
		libIDs = append(libIDs, id)
	}
	sort.Strings(libIDs)
	for _, id := range libIDs {
		h := c.libs[id]
		out.Libraries = append(out.Libraries, cdx.AILibrary{
			ID: h.def.ID, Name: h.def.Name, Provider: h.def.Provider,
			Languages: h.def.Languages, Purl: purlFor(h.def),
			Confidence: "high", Evidence: h.evidence,
		})
	}

	modelKeys := make([]string, 0, len(c.models))
	for k := range c.models {
		modelKeys = append(modelKeys, k)
	}
	sort.Strings(modelKeys)
	for _, k := range modelKeys {
		h := c.models[k]
		conf := "medium"
		if h.known {
			conf = "high"
		}
		out.Models = append(out.Models, cdx.AIModel{
			Name: h.name, Provider: h.provider, Family: h.family, ViaSDK: h.viaSDK,
			Task: h.task, Known: h.known, Occurrences: h.occur,
			Confidence: conf, Evidence: h.evidence,
		})
	}

	return out
}

func toolConfidence(h *toolHit) string {
	if h.def.Type == "convention" {
		return "medium"
	}
	for cat, n := range h.counts {
		if n > 0 && strongCategories[cat] {
			return "high"
		}
	}
	if h.counts["config"] > 0 || h.counts["ignore"] > 0 {
		return "medium"
	}
	return "low"
}

// ---- shared helpers ------------------------------------------------------

type extracted struct {
	value string
	line  int
}

// findSubmatches returns the first capture group of every match, with the
// 1-based line number of the match start.
func findSubmatches(content string, re *regexp.Regexp) []extracted {
	locs := re.FindAllStringSubmatchIndex(content, -1)
	if locs == nil {
		return nil
	}
	out := make([]extracted, 0, len(locs))
	for _, loc := range locs {
		if len(loc) < 4 || loc[2] < 0 {
			continue
		}
		out = append(out, extracted{
			value: content[loc[2]:loc[3]],
			line:  1 + strings.Count(content[:loc[0]], "\n"),
		})
	}
	return out
}

func anyMatch(res []*regexp.Regexp, content string) bool {
	for _, re := range res {
		if re.MatchString(content) {
			return true
		}
	}
	return false
}

func intersect(a, b map[string]bool) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

// plausibleModel rejects values that cannot be a model identifier (templates,
// prose, empty), while still accepting unknown/future literals.
func plausibleModel(name string) bool {
	if name == "" || len(name) > 120 {
		return false
	}
	if strings.ContainsAny(name, " \t\n\r{}$<>") {
		return false
	}
	return true
}

func purlFor(l LibraryDef) string {
	if len(l.PurlNames) == 0 {
		return ""
	}
	ecos := make([]string, 0, len(l.PurlNames))
	for e := range l.PurlNames {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	eco := ecos[0]
	name := l.PurlNames[eco]
	if eco == "maven" {
		name = strings.ReplaceAll(name, ":", "/")
	}
	return fmt.Sprintf("pkg:%s/%s", eco, name)
}

// literalPrefix returns the fixed path prefix of a glob (everything before the
// first wildcard), used to probe for a tool's directory in the home dir.
func literalPrefix(glob string) string {
	i := strings.IndexAny(glob, "*?")
	if i < 0 {
		return glob
	}
	p := glob[:i]
	return strings.TrimRight(p, "/")
}
