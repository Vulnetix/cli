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

// InfraRuntimeDef describes one AI infrastructure runtime (model server,
// agent platform, vector database, training/eval framework) identified by
// container image reference patterns in IaC files.
type InfraRuntimeDef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Vendor   string `json:"vendor,omitempty"`
	Category string `json:"category"` // inference | agent | training | evaluation | vector-database | managed-ai | accelerator
	Homepage string `json:"homepage,omitempty"`
	// ImagePatterns are anchored RE2 regexes matched against the image NAME
	// (repository incl. registry, tag/digest already split off). Patterns are
	// deliberately narrow (official orgs/registries only): mirrored or private
	// copies are a documented false negative, not a guess.
	ImagePatterns []string `json:"image_patterns"`
}

// WorkloadEnvSignal maps an environment variable NAME observed on a workload
// container to an AI framework. Only the name is ever matched — values are
// never read.
type WorkloadEnvSignal struct {
	Env       string `json:"env"`
	Framework string `json:"framework"` // infra id reported when this signal fires
	Name      string `json:"name"`      // display name
	Category  string `json:"category"`
}

// CRDFieldDef pulls one string field out of a matched CRD document.
type CRDFieldDef struct {
	Path string `json:"path"` // dot-path, e.g. spec.predictor.model.storageUri
	As   string `json:"as"`   // model | runtime | runtime_version | runtime_ref | service_account
}

// CRDDef matches a Kubernetes custom resource kind that declares AI workloads.
type CRDDef struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	APIVersionPrefix string        `json:"api_version_prefix"` // e.g. "serving.kserve.io/"
	Kind             string        `json:"kind"`
	Category         string        `json:"category"`
	Homepage         string        `json:"homepage,omitempty"`
	Fields           []CRDFieldDef `json:"fields,omitempty"`
}

// TerraformSignalDef matches a managed-AI or accelerator resource in
// Terraform/OpenTofu files (regex over content — consistent with the rest of
// the IaC scanning, which does not structurally parse HCL).
type TerraformSignalDef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"` // managed-ai | accelerator
	Provider string `json:"provider,omitempty"`
	// ResourcePattern matches the resource TYPE (first label of a resource
	// block), e.g. ^google_vertex_ai_.
	ResourcePattern string `json:"resource_pattern"`
	// AttrPattern optionally further gates on block content (e.g. kind = "OpenAI").
	AttrPattern string `json:"attr_pattern,omitempty"`
}

// InfrastructureDef is the IaC detection section of the catalog.
type InfrastructureDef struct {
	Runtimes             []InfraRuntimeDef    `json:"runtimes,omitempty"`
	ModelEnvVars         []string             `json:"model_env_vars,omitempty"`
	ModelArgFlags        []string             `json:"model_arg_flags,omitempty"`
	ModelMountPrefixes   []string             `json:"model_mount_prefixes,omitempty"`
	DatasetVolumeNames   []string             `json:"dataset_volume_names,omitempty"`
	DatasetMountPrefixes []string             `json:"dataset_mount_prefixes,omitempty"`
	WorkloadEnvSignals   []WorkloadEnvSignal  `json:"workload_env_signals,omitempty"`
	AnnotationPrefixes   []string             `json:"annotation_prefixes,omitempty"`
	CRDs                 []CRDDef             `json:"crds,omitempty"`
	CategoryPriority     []string             `json:"category_priority,omitempty"`
	GPUResourceKeys      []string             `json:"gpu_resource_keys,omitempty"`
	TerraformSignals     []TerraformSignalDef `json:"terraform_signals,omitempty"`
	ModelFileExtensions  []string             `json:"model_file_extensions,omitempty"`
}

// Catalog is the raw (uncompiled) detection catalog.
type Catalog struct {
	Version        string             `json:"version"`
	Tools          []ToolDef          `json:"tools"`
	Libraries      []LibraryDef       `json:"libraries"`
	Families       []FamilyDef        `json:"model_families"`
	Infrastructure *InfrastructureDef `json:"infrastructure,omitempty"`
}

// ---- compiled forms ------------------------------------------------------

// CompiledCatalog is the catalog with all regexes compiled and validated.
type CompiledCatalog struct {
	Version   string
	Tools     []CompiledTool
	Libraries []CompiledLibrary
	Families  []CompiledFamily
	Infra     *CompiledInfrastructure // nil when the catalog has no infrastructure section
}

type CompiledInfraRuntime struct {
	Def    InfraRuntimeDef
	Images []*regexp.Regexp
}

type CompiledTerraformSignal struct {
	Def        TerraformSignalDef
	ResourceRe *regexp.Regexp
	AttrRe     *regexp.Regexp // nil when no attr gate
}

// CompiledInfrastructure holds the validated IaC detection rules.
type CompiledInfrastructure struct {
	Runtimes             []CompiledInfraRuntime
	ModelEnvVars         map[string]bool
	ModelArgFlags        map[string]bool
	ModelMountPrefixes   []string
	DatasetVolumeNames   map[string]bool
	DatasetMountPrefixes []string
	EnvSignals           map[string]WorkloadEnvSignal // env var name -> signal
	AnnotationPrefixes   []string
	CRDs                 []CRDDef
	CategoryRank         map[string]int // lower = higher priority
	GPUResourceKeys      map[string]bool
	Terraform            []CompiledTerraformSignal
	ModelFileExts        map[string]bool
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
	if f.Infrastructure != nil {
		mergeInfrastructure(cat, f.Infrastructure)
	}
	return nil
}

// mergeInfrastructure merges an infrastructure section: runtimes/CRDs/
// terraform signals upsert by id, env signals upsert by env name, and a
// non-empty scalar list from a later file REPLACES the earlier list (so an
// override catalog narrowing an allowlist is honored).
func mergeInfrastructure(cat *Catalog, in *InfrastructureDef) {
	if cat.Infrastructure == nil {
		cat.Infrastructure = &InfrastructureDef{}
	}
	dst := cat.Infrastructure
	for _, r := range in.Runtimes {
		replaced := false
		for i := range dst.Runtimes {
			if dst.Runtimes[i].ID == r.ID {
				dst.Runtimes[i] = r
				replaced = true
				break
			}
		}
		if !replaced {
			dst.Runtimes = append(dst.Runtimes, r)
		}
	}
	for _, c := range in.CRDs {
		replaced := false
		for i := range dst.CRDs {
			if dst.CRDs[i].ID == c.ID {
				dst.CRDs[i] = c
				replaced = true
				break
			}
		}
		if !replaced {
			dst.CRDs = append(dst.CRDs, c)
		}
	}
	for _, ts := range in.TerraformSignals {
		replaced := false
		for i := range dst.TerraformSignals {
			if dst.TerraformSignals[i].ID == ts.ID {
				dst.TerraformSignals[i] = ts
				replaced = true
				break
			}
		}
		if !replaced {
			dst.TerraformSignals = append(dst.TerraformSignals, ts)
		}
	}
	for _, s := range in.WorkloadEnvSignals {
		replaced := false
		for i := range dst.WorkloadEnvSignals {
			if dst.WorkloadEnvSignals[i].Env == s.Env {
				dst.WorkloadEnvSignals[i] = s
				replaced = true
				break
			}
		}
		if !replaced {
			dst.WorkloadEnvSignals = append(dst.WorkloadEnvSignals, s)
		}
	}
	if len(in.ModelEnvVars) > 0 {
		dst.ModelEnvVars = in.ModelEnvVars
	}
	if len(in.ModelArgFlags) > 0 {
		dst.ModelArgFlags = in.ModelArgFlags
	}
	if len(in.ModelMountPrefixes) > 0 {
		dst.ModelMountPrefixes = in.ModelMountPrefixes
	}
	if len(in.DatasetVolumeNames) > 0 {
		dst.DatasetVolumeNames = in.DatasetVolumeNames
	}
	if len(in.DatasetMountPrefixes) > 0 {
		dst.DatasetMountPrefixes = in.DatasetMountPrefixes
	}
	if len(in.AnnotationPrefixes) > 0 {
		dst.AnnotationPrefixes = in.AnnotationPrefixes
	}
	if len(in.CategoryPriority) > 0 {
		dst.CategoryPriority = in.CategoryPriority
	}
	if len(in.GPUResourceKeys) > 0 {
		dst.GPUResourceKeys = in.GPUResourceKeys
	}
	if len(in.ModelFileExtensions) > 0 {
		dst.ModelFileExtensions = in.ModelFileExtensions
	}
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

	if c.Infrastructure != nil {
		ci, err := compileInfrastructure(c.Infrastructure)
		if err != nil {
			return nil, err
		}
		cc.Infra = ci
	}

	return cc, nil
}

// compileInfrastructure validates and compiles the IaC detection rules.
// Every failure is fail-fast at load time so a malformed pattern can never
// surface mid-scan.
func compileInfrastructure(in *InfrastructureDef) (*CompiledInfrastructure, error) {
	ci := &CompiledInfrastructure{
		ModelEnvVars:         map[string]bool{},
		ModelArgFlags:        map[string]bool{},
		DatasetVolumeNames:   map[string]bool{},
		EnvSignals:           map[string]WorkloadEnvSignal{},
		CategoryRank:         map[string]int{},
		GPUResourceKeys:      map[string]bool{},
		ModelFileExts:        map[string]bool{},
		ModelMountPrefixes:   in.ModelMountPrefixes,
		DatasetMountPrefixes: in.DatasetMountPrefixes,
		AnnotationPrefixes:   in.AnnotationPrefixes,
		CRDs:                 in.CRDs,
	}

	for i, cat := range in.CategoryPriority {
		ci.CategoryRank[cat] = i
	}
	validCategory := func(kind, id, cat string) error {
		if cat == "" {
			return fmt.Errorf("infrastructure %s %s: category is required", kind, id)
		}
		if len(ci.CategoryRank) > 0 {
			if _, ok := ci.CategoryRank[cat]; !ok {
				return fmt.Errorf("infrastructure %s %s: category %q not in category_priority", kind, id, cat)
			}
		}
		return nil
	}

	seenRuntime := map[string]bool{}
	for _, r := range in.Runtimes {
		if r.ID == "" {
			return nil, fmt.Errorf("infrastructure runtime with empty id")
		}
		if seenRuntime[r.ID] {
			return nil, fmt.Errorf("infrastructure runtime %s: duplicate id", r.ID)
		}
		seenRuntime[r.ID] = true
		if err := validCategory("runtime", r.ID, r.Category); err != nil {
			return nil, err
		}
		if len(r.ImagePatterns) == 0 {
			return nil, fmt.Errorf("infrastructure runtime %s: image_patterns is required", r.ID)
		}
		cr := CompiledInfraRuntime{Def: r}
		for _, p := range r.ImagePatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("infrastructure runtime %s: image pattern %q: %w", r.ID, p, err)
			}
			cr.Images = append(cr.Images, re)
		}
		ci.Runtimes = append(ci.Runtimes, cr)
	}

	for _, v := range in.ModelEnvVars {
		if v == "" {
			return nil, fmt.Errorf("infrastructure model_env_vars: empty entry")
		}
		ci.ModelEnvVars[v] = true
	}
	for _, f := range in.ModelArgFlags {
		if !strings.HasPrefix(f, "-") {
			return nil, fmt.Errorf("infrastructure model_arg_flags: %q must start with '-'", f)
		}
		ci.ModelArgFlags[f] = true
	}
	for _, p := range append(append([]string{}, in.ModelMountPrefixes...), in.DatasetMountPrefixes...) {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("infrastructure mount prefix %q must be absolute", p)
		}
	}
	for _, n := range in.DatasetVolumeNames {
		ci.DatasetVolumeNames[n] = true
	}
	for _, s := range in.WorkloadEnvSignals {
		if s.Env == "" || s.Framework == "" {
			return nil, fmt.Errorf("infrastructure workload_env_signal needs env and framework: %+v", s)
		}
		if err := validCategory("env signal", s.Env, s.Category); err != nil {
			return nil, err
		}
		ci.EnvSignals[s.Env] = s
	}
	for _, crd := range in.CRDs {
		if crd.ID == "" || crd.Kind == "" || crd.APIVersionPrefix == "" {
			return nil, fmt.Errorf("infrastructure crd %q needs id, kind and api_version_prefix", crd.ID)
		}
		if err := validCategory("crd", crd.ID, crd.Category); err != nil {
			return nil, err
		}
		for _, f := range crd.Fields {
			if f.Path == "" || strings.HasPrefix(f.Path, ".") || strings.HasSuffix(f.Path, ".") {
				return nil, fmt.Errorf("infrastructure crd %s: invalid field path %q", crd.ID, f.Path)
			}
		}
	}
	for _, k := range in.GPUResourceKeys {
		ci.GPUResourceKeys[k] = true
	}
	for _, ts := range in.TerraformSignals {
		if ts.ID == "" || ts.ResourcePattern == "" {
			return nil, fmt.Errorf("infrastructure terraform signal %q needs id and resource_pattern", ts.ID)
		}
		if err := validCategory("terraform signal", ts.ID, ts.Category); err != nil {
			return nil, err
		}
		cts := CompiledTerraformSignal{Def: ts}
		re, err := regexp.Compile(ts.ResourcePattern)
		if err != nil {
			return nil, fmt.Errorf("infrastructure terraform signal %s: resource_pattern %q: %w", ts.ID, ts.ResourcePattern, err)
		}
		cts.ResourceRe = re
		if ts.AttrPattern != "" {
			are, err := regexp.Compile(ts.AttrPattern)
			if err != nil {
				return nil, fmt.Errorf("infrastructure terraform signal %s: attr_pattern %q: %w", ts.ID, ts.AttrPattern, err)
			}
			cts.AttrRe = are
		}
		ci.Terraform = append(ci.Terraform, cts)
	}
	for _, ext := range in.ModelFileExtensions {
		if !strings.HasPrefix(ext, ".") {
			return nil, fmt.Errorf("infrastructure model_file_extensions: %q must start with '.'", ext)
		}
		ci.ModelFileExts[strings.ToLower(ext)] = true
	}

	return ci, nil
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
