package cbom

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

const (
	// defaultMaxDepth bounds the filesystem walk when the caller does not set one.
	defaultMaxDepth = 64
	// maxContentFileSize caps the size of a file whose contents are scanned.
	maxContentFileSize = 1 << 20
	// maxEvidenceCollect caps retained evidence per detection in memory.
	maxEvidenceCollect = 200
	// maxSnippet bounds an evidence snippet's length.
	maxSnippet = 160
)

// Options controls a CBOM detection run.
type Options struct {
	Root        string
	MaxDepth    int
	Ignore      []string
	ScanSource  bool
	ScanConfig  bool
	ScanCerts   bool
	ScanDeps    bool
	IncludeHome bool
	Catalog     *CompiledCatalog
	// RespectGitignore prunes .gitignored paths (default off; the cbom command
	// sets it true unless --cbom-include-ignored is passed).
	RespectGitignore bool
}

// Detect runs the enabled passes and returns CycloneDX-ready crypto detections.
func Detect(opts Options) (cdx.CryptoDetections, error) {
	if opts.Catalog == nil {
		return cdx.CryptoDetections{}, fmt.Errorf("cbom: nil catalog")
	}
	root := opts.Root
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return cdx.CryptoDetections{}, err
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
		return cdx.CryptoDetections{}, err
	}
	// Load text contents once (shared by source/config/deps); binaries skipped.
	sast.LoadFileContentsWithOptions(input, sast.LoadOptions{MaxFileSize: maxContentFileSize, IgnoreBinaries: true})

	c := &collector{
		cat:   opts.Catalog,
		root:  abs,
		algos: map[string]*algoHit{},
		libs:  map[string]*libHit{},
	}
	if opts.ScanSource {
		c.detectSource(input)
	}
	if opts.ScanConfig {
		c.detectConfig(input)
	}
	if opts.ScanCerts {
		c.detectCerts(input)
	}
	if opts.ScanDeps {
		c.detectDeps(input)
	}
	return c.result(), nil
}

// ---- collector -----------------------------------------------------------

type collector struct {
	cat   *CompiledCatalog
	root  string
	algos map[string]*algoHit
	libs  map[string]*libHit
	certs []cdx.CryptoCert
}

type algoHit struct {
	def      AlgorithmDef
	paramSet string
	mode     string
	padding  string
	curve    string
	occur    int
	evidence []cdx.CryptoEvidence
	seenLoc  map[string]bool
}

type libHit struct {
	def      LibraryDef
	evidence []cdx.CryptoEvidence
}

// addAlgo records a hit for an algorithm, merging case/separator variants under
// the single canonical SPDX id and keeping the first-seen parameter set / mode /
// padding. Evidence is deduplicated by locator.
func (c *collector) addAlgo(a *CompiledAlgorithm, ev cdx.CryptoEvidence, paramSet, mode, padding string) {
	h := c.algos[a.Def.ID]
	if h == nil {
		h = &algoHit{
			def:      a.Def,
			paramSet: a.Def.ParameterSet,
			mode:     a.Def.Mode,
			padding:  a.Def.Padding,
			curve:    a.Def.Curve,
			seenLoc:  map[string]bool{},
		}
		c.algos[a.Def.ID] = h
	}
	if paramSet != "" && h.paramSet == "" {
		h.paramSet = paramSet
	}
	if mode != "" && h.mode == "" {
		h.mode = mode
	}
	if padding != "" && h.padding == "" {
		h.padding = padding
	}
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

func (c *collector) addLib(def LibraryDef, ev cdx.CryptoEvidence) {
	h := c.libs[def.ID]
	if h == nil {
		h = &libHit{def: def}
		c.libs[def.ID] = h
	}
	if len(h.evidence) < maxEvidenceCollect {
		h.evidence = append(h.evidence, ev)
	}
}

func (c *collector) result() cdx.CryptoDetections {
	out := cdx.CryptoDetections{CatalogVersion: c.cat.Version}

	for _, id := range sortedKeys(c.algos) {
		h := c.algos[id]
		out.Assets = append(out.Assets, cdx.CryptoAsset{
			SPDXID:                   h.def.ID,
			Name:                     h.def.Name,
			OID:                      h.def.OID,
			Primitive:                h.def.Primitive,
			ParameterSetIdentifier:   h.paramSet,
			Curve:                    h.curve,
			Mode:                     h.mode,
			Padding:                  h.padding,
			CryptoFunctions:          h.def.CryptoFunctions,
			ClassicalSecurityLevel:   h.def.ClassicalSecurityLevel,
			NISTQuantumSecurityLevel: h.def.NISTQuantumLevel,
			PQCStatus:                h.def.PQCStatus,
			Standards:                h.def.Standards,
			Confidence:               "high",
			Occurrences:              h.occur,
			Evidence:                 h.evidence,
		})
	}

	for _, id := range sortedKeys(c.libs) {
		h := c.libs[id]
		out.Libraries = append(out.Libraries, cdx.CryptoLib{
			ID:         h.def.ID,
			Name:       h.def.Name,
			Provider:   h.def.Provider,
			Languages:  h.def.Languages,
			Purl:       purlFor(h.def),
			Confidence: "high",
			Evidence:   h.evidence,
		})
	}

	out.Certificates = c.certs
	out.Summary = cdx.ComputeCryptoSummary(out)
	return out
}

// ---- shared helpers ------------------------------------------------------

func itoa(i int) string { return strconv.Itoa(i) }

func locOf(path string, line int) string {
	if line > 0 {
		return path + ":" + itoa(line)
	}
	return path
}

type lineMatch struct {
	line int
	text string
}

// matchLines returns each whole-match's line number and a trimmed snippet.
func matchLines(content string, re *regexp.Regexp) []lineMatch {
	locs := re.FindAllStringIndex(content, -1)
	out := make([]lineMatch, 0, len(locs))
	for _, loc := range locs {
		out = append(out, lineMatch{
			line: 1 + strings.Count(content[:loc[0]], "\n"),
			text: trimSnippet(content[loc[0]:loc[1]]),
		})
	}
	return out
}

type capMatch struct {
	value string
	line  int
}

// findCaptures returns the first capture group of every match with its line.
func findCaptures(content string, re *regexp.Regexp) []capMatch {
	locs := re.FindAllStringSubmatchIndex(content, -1)
	out := make([]capMatch, 0, len(locs))
	for _, loc := range locs {
		if len(loc) < 4 || loc[2] < 0 {
			continue
		}
		out = append(out, capMatch{
			value: content[loc[2]:loc[3]],
			line:  1 + strings.Count(content[:loc[0]], "\n"),
		})
	}
	return out
}

func trimSnippet(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\t", " "))
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > maxSnippet {
		s = s[:maxSnippet]
	}
	return s
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalizeMode maps a token to a CycloneDX mode enum value, or "" if unknown.
func normalizeMode(tok string) string {
	switch strings.ToLower(tok) {
	case "cbc":
		return "cbc"
	case "ecb":
		return "ecb"
	case "ccm":
		return "ccm"
	case "gcm":
		return "gcm"
	case "cfb":
		return "cfb"
	case "ofb":
		return "ofb"
	case "ctr":
		return "ctr"
	}
	return ""
}

// normalizePadding maps a token to a CycloneDX padding enum value, or "".
func normalizePadding(tok string) string {
	t := strings.ToLower(tok)
	switch {
	case strings.HasPrefix(t, "pkcs5"):
		return "pkcs5"
	case strings.HasPrefix(t, "pkcs7"):
		return "pkcs7"
	case strings.HasPrefix(t, "pkcs1"):
		return "pkcs1v15"
	case strings.HasPrefix(t, "oaep"):
		return "oaep"
	case strings.HasPrefix(t, "nopadding"), t == "none", t == "raw":
		return "raw"
	}
	return ""
}

func intersectLangs(want map[string]bool, have map[string]bool) bool {
	for l := range want {
		if have[l] {
			return true
		}
	}
	return false
}

func intersectLangSlice(want []string, have map[string]bool) bool {
	for _, l := range want {
		if have[canonicalLang(l)] {
			return true
		}
	}
	return false
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

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
