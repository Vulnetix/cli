// Package aibom discovers evidence of AI coding agents and AI-SDK usage in a
// codebase and maps it to a CycloneDX AI Bill of Materials.
//
// All detection is driven by a declarative catalog (internal/aibom/catalog/*.json)
// so the rules — env-var names, tool directories/files, SDK import patterns and
// the SDK parameters that carry model names — can be maintained over time without
// code changes. The catalog is embedded in the binary and can be extended or
// overridden at runtime with --catalog.
package aibom

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

//go:embed catalog/*.json
var catalogFS embed.FS

// ToolDef describes one AI coding agent / assistant and the on-disk + environment
// evidence that identifies it.
type ToolDef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Vendor   string `json:"vendor"`
	Type     string `json:"type"` // cli-agent | ide-extension | ide | service
	Homepage string `json:"homepage,omitempty"`
	// Env are environment variable names (exact, or globs with '*') that this
	// tool sets. Only the NAME and presence are ever recorded — never the value.
	Env []string `json:"env,omitempty"`
	// Paths maps an evidence category (config, instructions, ignore, skills,
	// hooks, plugins, steering, memory, prompts, agents, commands, marketplace)
	// to a list of repo-relative path globs ('*', '**', '?' supported).
	Paths map[string][]string `json:"paths,omitempty"`
	// ModelConfigExtractors pull model-name literals out of this tool's own
	// config files.
	ModelConfigExtractors []ConfigExtractor `json:"model_config_extractors,omitempty"`
	// CommitPatterns are regexes matched against each commit's author/committer
	// identity and message (e.g. a "Co-Authored-By: Claude <noreply@anthropic.com>"
	// trailer, a "Claude-Session:" line, an agent bot author, or a "Generated
	// with <tool>" marker). They identify commits authored by this agent in git
	// history. No capture group required — these are presence signals.
	CommitPatterns []string `json:"commit_patterns,omitempty"`
}

// ConfigExtractor extracts a model name from a tool config file, either by a
// JSON/YAML key or a regex with a single capture group.
type ConfigExtractor struct {
	FileGlob string `json:"file_glob"`
	JSONKey  string `json:"json_key,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
}

// LibraryDef describes one AI SDK / framework and how to detect its use and
// extract the model names passed to it.
type LibraryDef struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Provider  string            `json:"provider"`
	Languages []string          `json:"languages"`
	PurlNames map[string]string `json:"purl_names,omitempty"` // ecosystem -> package name
	// ImportPatterns confirm the library is in use (import/require/use lines).
	ImportPatterns []string `json:"import_patterns"`
	// ModelExtractors capture the model-name literal bound to a known SDK
	// parameter. Anchoring on the parameter (not the value) is what makes
	// unknown/future model names detectable.
	ModelExtractors []ModelExtractor `json:"model_extractors,omitempty"`
}

// ModelExtractor is a regex with exactly one capture group = the model literal.
type ModelExtractor struct {
	Param   string `json:"param"`
	Pattern string `json:"pattern"`
	Task    string `json:"task,omitempty"` // chat | embedding | image | completion | ...
}

// FamilyDef maps a model-name prefix pattern to a provider/family. It only
// enriches confidence — it never suppresses an unknown literal.
type FamilyDef struct {
	PrefixRegex string `json:"prefix_regex"`
	Provider    string `json:"provider"`
	Family      string `json:"family"`
}

// Catalog is the raw (uncompiled) detection catalog.
type Catalog struct {
	Version   string       `json:"version"`
	Tools     []ToolDef    `json:"tools"`
	Libraries []LibraryDef `json:"libraries"`
	Families  []FamilyDef  `json:"model_families"`
}

// ---- compiled forms ------------------------------------------------------

// CompiledCatalog is the catalog with all regexes compiled and validated.
type CompiledCatalog struct {
	Version   string
	Tools     []CompiledTool
	Libraries []CompiledLibrary
	Families  []CompiledFamily
}

type CompiledTool struct {
	Def        ToolDef
	EnvExact   map[string]bool
	EnvGlobs   []*regexp.Regexp
	Paths      []CompiledPathRule
	Extractors []CompiledExtractor
	Commits    []*regexp.Regexp
}

type CompiledPathRule struct {
	Category string
	Raw      string
	Re       *regexp.Regexp // nil when Exact
	Exact    bool
}

type CompiledExtractor struct {
	FileGlob *regexp.Regexp
	JSONKey  string
	Re       *regexp.Regexp // nil when JSONKey is used
}

type CompiledLibrary struct {
	Def     LibraryDef
	Langs   map[string]bool
	Imports []*regexp.Regexp
	Models  []CompiledModelExtractor
}

type CompiledModelExtractor struct {
	Param string
	Task  string
	Re    *regexp.Regexp
}

type CompiledFamily struct {
	Def FamilyDef
	Re  *regexp.Regexp
}

// DefaultCatalog parses and merges the embedded catalog files.
func DefaultCatalog() (*Catalog, error) {
	cat := &Catalog{}
	entries, err := catalogFS.ReadDir("catalog")
	if err != nil {
		return nil, fmt.Errorf("reading embedded catalog: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := catalogFS.ReadFile("catalog/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading catalog/%s: %w", e.Name(), err)
		}
		if err := mergeInto(cat, data, "catalog/"+e.Name()); err != nil {
			return nil, err
		}
	}
	return cat, nil
}

// LoadCatalog returns the catalog to use for a scan. When noBuiltin is false the
// embedded catalog is loaded first; when overridePath is non-empty that file is
// merged on top (entries with a matching id replace the builtin; new ids are
// appended).
func LoadCatalog(overridePath string, noBuiltin bool) (*Catalog, error) {
	cat := &Catalog{Version: "builtin"}
	if !noBuiltin {
		c, err := DefaultCatalog()
		if err != nil {
			return nil, err
		}
		cat = c
	}
	if overridePath != "" {
		data, err := os.ReadFile(overridePath)
		if err != nil {
			return nil, fmt.Errorf("reading --catalog %s: %w", overridePath, err)
		}
		if err := mergeInto(cat, data, overridePath); err != nil {
			return nil, err
		}
	}
	if cat.Version == "" {
		cat.Version = "custom"
	}
	return cat, nil
}

// mergeInto parses a catalog file and merges its entries into cat, overriding by id.
func mergeInto(cat *Catalog, data []byte, src string) error {
	var f Catalog
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing %s: %w", src, err)
	}
	if f.Version != "" {
		cat.Version = f.Version
	}
	for _, t := range f.Tools {
		cat.Tools = upsertTool(cat.Tools, t)
	}
	for _, l := range f.Libraries {
		cat.Libraries = upsertLibrary(cat.Libraries, l)
	}
	cat.Families = append(cat.Families, f.Families...)
	return nil
}

func upsertTool(list []ToolDef, t ToolDef) []ToolDef {
	for i := range list {
		if list[i].ID == t.ID {
			list[i] = t
			return list
		}
	}
	return append(list, t)
}

func upsertLibrary(list []LibraryDef, l LibraryDef) []LibraryDef {
	for i := range list {
		if list[i].ID == l.ID {
			list[i] = l
			return list
		}
	}
	return append(list, l)
}

// Compile compiles and validates every regex/glob in the catalog. It is the
// single validation gate used by both the runtime detector and the docs
// generator, so a malformed pattern fails fast and identically in both.
func (c *Catalog) Compile() (*CompiledCatalog, error) {
	cc := &CompiledCatalog{Version: c.Version}

	for _, t := range c.Tools {
		ct := CompiledTool{Def: t, EnvExact: map[string]bool{}}
		for _, e := range t.Env {
			if strings.ContainsAny(e, "*?") {
				re, err := globToRegexp(e)
				if err != nil {
					return nil, fmt.Errorf("tool %s: env glob %q: %w", t.ID, e, err)
				}
				ct.EnvGlobs = append(ct.EnvGlobs, re)
			} else {
				ct.EnvExact[e] = true
			}
		}
		for cat, globs := range t.Paths {
			for _, g := range globs {
				rule := CompiledPathRule{Category: cat, Raw: g}
				if strings.ContainsAny(g, "*?") {
					re, err := globToRegexp(g)
					if err != nil {
						return nil, fmt.Errorf("tool %s: path glob %q: %w", t.ID, g, err)
					}
					rule.Re = re
				} else {
					rule.Exact = true
				}
				ct.Paths = append(ct.Paths, rule)
			}
		}
		for _, ex := range t.ModelConfigExtractors {
			fg, err := globToRegexp(ex.FileGlob)
			if err != nil {
				return nil, fmt.Errorf("tool %s: extractor file_glob %q: %w", t.ID, ex.FileGlob, err)
			}
			ce := CompiledExtractor{FileGlob: fg, JSONKey: ex.JSONKey}
			if ex.Pattern != "" {
				re, err := regexp.Compile(ex.Pattern)
				if err != nil {
					return nil, fmt.Errorf("tool %s: extractor pattern %q: %w", t.ID, ex.Pattern, err)
				}
				if re.NumSubexp() < 1 {
					return nil, fmt.Errorf("tool %s: extractor pattern %q needs a capture group", t.ID, ex.Pattern)
				}
				ce.Re = re
			}
			if ce.JSONKey == "" && ce.Re == nil {
				return nil, fmt.Errorf("tool %s: extractor must set json_key or pattern", t.ID)
			}
			ct.Extractors = append(ct.Extractors, ce)
		}
		for _, p := range t.CommitPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("tool %s: commit pattern %q: %w", t.ID, p, err)
			}
			ct.Commits = append(ct.Commits, re)
		}
		cc.Tools = append(cc.Tools, ct)
	}

	for _, l := range c.Libraries {
		cl := CompiledLibrary{Def: l, Langs: map[string]bool{}}
		for _, lang := range l.Languages {
			cl.Langs[strings.ToLower(lang)] = true
		}
		for _, p := range l.ImportPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("library %s: import pattern %q: %w", l.ID, p, err)
			}
			cl.Imports = append(cl.Imports, re)
		}
		for _, me := range l.ModelExtractors {
			re, err := regexp.Compile(me.Pattern)
			if err != nil {
				return nil, fmt.Errorf("library %s: model extractor %q: %w", l.ID, me.Pattern, err)
			}
			if re.NumSubexp() < 1 {
				return nil, fmt.Errorf("library %s: model extractor %q needs a capture group", l.ID, me.Pattern)
			}
			cl.Models = append(cl.Models, CompiledModelExtractor{Param: me.Param, Task: me.Task, Re: re})
		}
		cc.Libraries = append(cc.Libraries, cl)
	}

	for _, f := range c.Families {
		re, err := regexp.Compile(f.PrefixRegex)
		if err != nil {
			return nil, fmt.Errorf("model family %q: %w", f.PrefixRegex, err)
		}
		cc.Families = append(cc.Families, CompiledFamily{Def: f, Re: re})
	}

	return cc, nil
}

// classifyModel returns the provider/family for a model literal, and whether it
// matched a known family. Unknown literals are still returned (Known=false) so
// future model names are never dropped.
func (cc *CompiledCatalog) classifyModel(name, sdkProvider string) (provider, family string, known bool) {
	for _, f := range cc.Families {
		if f.Re.MatchString(name) {
			return f.Def.Provider, f.Def.Family, true
		}
	}
	return sdkProvider, "", false
}

// globToRegexp converts a path/name glob to an anchored regexp.
//   - "**/"  matches any number of leading directories (including none)
//   - "**"   matches across directory separators
//   - "*"    matches within a single path segment
//   - "?"    matches a single non-separator char
func globToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i += 2
				if i < len(glob) && glob[i] == '/' {
					b.WriteString("(?:.*/)?")
					i++
				} else {
					b.WriteString(".*")
				}
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		default:
			if strings.IndexByte(`.+()|[]{}^$\`, c) >= 0 {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
			i++
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
