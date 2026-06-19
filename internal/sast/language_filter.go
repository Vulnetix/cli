package sast

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Language pre-filter: most embedded rules declare a `metadata.languages` set and
// gate their bodies on the matching file extension (e.g. `endswith(path, ".go")`).
// A rule whose declared languages are entirely absent from the repository can
// never produce a finding, so compiling and evaluating it is wasted work. Before
// compiling, we drop those rules — cutting both the (dominant) compile cost and
// the eval cost in proportion to how single-language the repo is.
//
// Rules with no `languages` key, an empty set, or the "generic" marker are
// universal (e.g. secrets rules that scan all file contents) and always kept. A
// rule that declares an unrecognised language is also kept (fail-open), so the
// filter can only ever skip rules we are confident are inapplicable.

// languageAliases collapses related metadata labels onto a single canonical
// ecosystem key, so that "javascript", "node" and "typescript" all resolve to
// the same extension set ("javascript implies the entire ecosystem").
var languageAliases = map[string]string{
	"node":        "javascript",
	"typescript":  "javascript",
	"js":          "javascript",
	"ts":          "javascript",
	"shell":       "bash",
	"sh":          "bash",
	"golang":      "go",
	"c++":         "cpp",
	"c#":          "csharp",
	"dotnet":      "csharp",
	"objective-c": "cpp",
}

// languageExtensions maps a canonical ecosystem key to the file extensions
// (lowercase, leading dot, suffix-matched) that indicate it is present. Compiled
// from an exhaustive per-ecosystem enumeration. Shared/ambiguous extensions are
// deliberately listed under EVERY plausible claimant (e.g. ".h" under c+cpp,
// ".erb" under ruby+html, ".gql" under graphql+sql): over-detecting a language
// only keeps a few extra rules, whereas under-detecting would wrongly skip a
// language's rules and miss findings. Language-agnostic config/lock/binary
// extensions are intentionally excluded so they don't mark a language present
// everywhere. Multi-dot suffixes (".d.ts", ".blade.php") are suffix-matched.
var languageExtensions = map[string][]string{
	"python": {
		".py", ".pyi", ".pyw", ".pyx", ".pxd", ".pxi", ".ipynb", ".rpy", ".pyt",
		".pyde", ".sage", ".spyx", ".cython", ".pyp", ".kv", ".pyf",
		// Starlark (Bazel/Buck/Pants) is a Python dialect with the same eval/exec surface
		".bzl", ".star", ".starlark", ".wsgi", ".tac",
	},
	// canonical for node / javascript / typescript (the whole JS/TS ecosystem)
	"javascript": {
		".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".cts", ".mts",
		".d.ts", ".d.cts", ".d.mts", ".vue", ".svelte", ".astro", ".mdx",
		".es6", ".es", ".mjml", ".coffee", ".litcoffee", ".iced", ".ls",
		".civet", ".gjs", ".gts", ".flow", ".marko", ".riot", ".cjsx",
	},
	"java": {
		".java", ".jav", ".jsh", ".jsp", ".jspx", ".jspf", ".tag", ".tagx",
		".tld", ".jstl", ".ftl", ".ftlh", ".ftlx", ".vm", ".gsp", ".jte",
		".aj", ".bsh", ".gradle", ".groovy", ".gvy", ".gy", ".gsh", ".jrxml",
		".jasper", ".g4", ".st", ".stg",
		// other JVM languages — java is the closest applicable ruleset
		".scala", ".sc", ".sbt", ".clj", ".cljs", ".cljc", ".edn",
	},
	"kotlin": {".kt", ".kts", ".ktm", ".gradle.kts"},
	// android apps are kotlin/java; rules gate on these + the manifest filename
	"android": {".kt", ".kts", ".aidl", ".smali", ".rsh", ".axml"},
	"go":      {".go", ".templ", ".gohtml", ".gotmpl", ".gotxt", ".tpl"},
	// .m = Objective-C impl, .cmake = CMake build script (C-family rulesets)
	"c": {".c", ".h", ".i", ".cats", ".ec", ".pgc", ".upc", ".inc", ".m", ".cmake"},
	"cpp": {
		".cpp", ".cc", ".cxx", ".c++", ".cp", ".hpp", ".hh", ".hxx", ".h++",
		".hp", ".h", ".ipp", ".tpp", ".txx", ".inl", ".ino", ".cu", ".cuh",
		".mm", ".cppm", ".ixx", ".tcc", ".inc", ".m", ".pch", ".cmake",
	},
	"php": {
		".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phtm",
		".phps", ".phpt", ".pht", ".ctp", ".inc", ".module", ".install",
		".theme", ".engine", ".profile", ".blade.php", ".latte", ".twig",
		".volt", ".tpl",
	},
	"ruby": {
		".rb", ".rbw", ".rbi", ".rbs", ".rake", ".gemspec", ".ru", ".erb",
		".rhtml", ".haml", ".slim", ".jbuilder", ".builder", ".rabl", ".thor",
		".podspec", ".arb", ".opal", ".god", ".axlsx", ".watchr",
	},
	"csharp": {
		".cs", ".csx", ".cshtml", ".razor", ".vb", ".fs", ".fsx", ".fsi",
		".il", ".aspx", ".ascx", ".ashx", ".asmx", ".asax", ".master",
		".xaml", ".axaml", ".cake", ".t4", ".tt", ".vbhtml", ".resx", ".resw",
		".asp", ".asa", ".dib", // classic ASP (vbscript/jscript) + .NET notebooks
	},
	"rust":      {".rs", ".rs.in"},
	"swift":     {".swift", ".swiftinterface", ".gyb", ".docc", ".xcconfig"},
	"terraform": {".tf", ".tfvars", ".hcl", ".tf.json", ".tfvars.json", ".nomad", ".pkr.hcl", ".sentinel", ".tofu"},
	"docker":    {".dockerfile", ".docker", ".containerfile"},
	// canonical for bash / shell
	"bash": {
		".sh", ".bash", ".zsh", ".ksh", ".ash", ".dash", ".mksh", ".pdksh",
		".csh", ".tcsh", ".fish", ".bats", ".command", ".ebuild", ".eclass",
		".zshrc", ".bashrc", ".nu", ".elv", ".mk", ".make",
	},
	"html": {
		".html", ".htm", ".xhtml", ".xht", ".shtml", ".dhtml", ".hta", ".haml",
		".slim", ".pug", ".jade", ".mustache", ".hbs", ".handlebars", ".ejs",
		".erb", ".njk", ".nunjucks", ".liquid", ".twig", ".mako", ".jinja",
		".jinja2", ".j2", ".soy", ".marko", ".vto", ".webc", ".heex", ".leex",
		".eex", ".gohtml", ".cshtml", ".vbhtml", ".vash", ".ftl", ".gsp",
		".latte", ".volt", ".tt2", ".tal", ".zpt", ".ace", ".amber", ".emblem",
		".ractive", ".swig",
		// docs/markup that embed injectable HTML/script
		".adoc", ".asciidoc", ".rst", ".markdown",
	},
	"sql": {
		".sql", ".ddl", ".dml", ".psql", ".pgsql", ".plsql", ".pls", ".pkb",
		".pks", ".pck", ".tsql", ".mysql", ".hql", ".cql", ".n1ql", ".sqlite",
		".sqlite3", ".ksql", ".sparksql", ".prql", ".surql", ".edgeql", ".bql",
		".sqlx", ".cyp", ".cypher", ".gql",
	},
	"graphql": {".graphql", ".gql", ".gqls", ".graphqls", ".sdl", ".prisma"},
}

// languageBasenameSubstrings maps a lowercase substring of a file's basename to
// the ecosystem(s) it indicates. Used for conventions that aren't a clean
// extension — e.g. docker rules gate on `contains(lower(base), "dockerfile")`, so
// "Dockerfile", "Dockerfile.prod", "service.containerfile" all count. Detection
// here MUST mirror how the rules themselves match, or a present language would be
// missed and its rules wrongly skipped.
var languageBasenameSubstrings = map[string][]string{
	"dockerfile":    {"docker"},
	"containerfile": {"docker"},
}

// languageFilenames maps exact lowercase base filenames to the canonical
// ecosystem(s) they indicate (for extension-less or fixed-name files).
var languageFilenames = map[string][]string{
	// Ruby DSLs (extension-less, unambiguous)
	"gemfile":     {"ruby"},
	"rakefile":    {"ruby"},
	"vagrantfile": {"ruby"},
	"brewfile":    {"ruby"},
	"fastfile":    {"ruby"},
	"appfile":     {"ruby"},
	"deliverfile": {"ruby"},
	"matchfile":   {"ruby"},
	"berksfile":   {"ruby"},
	"capfile":     {"ruby"},
	"guardfile":   {"ruby"},
	"dangerfile":  {"ruby"},
	"thorfile":    {"ruby"},
	"cheffile":    {"ruby"},
	"puppetfile":  {"ruby"},
	// Swift / Apple
	"podfile":       {"swift"},
	"package.swift": {"swift"},
	"cartfile":      {"swift"},
	// Go
	"go.mod":  {"go"},
	"go.sum":  {"go"},
	"go.work": {"go"},
	// JVM
	"build.gradle":     {"java", "android"},
	"build.gradle.kts": {"kotlin", "android"},
	"settings.gradle":  {"java", "android"},
	"pom.xml":          {"java"},
	"build.sbt":        {"java"},
	"deps.edn":         {"java"},
	"project.clj":      {"java"},
	"jenkinsfile":      {"java"},
	// Android native
	"androidmanifest.xml": {"android"},
	"android.mk":          {"android", "bash"},
	"application.mk":      {"android", "bash"},
	"proguard-rules.pro":  {"android"},
	// C / C++ build
	"cmakelists.txt": {"c", "cpp"},
	"configure.ac":   {"c", "bash"},
	"configure.in":   {"c", "bash"},
	"makefile.am":    {"c", "bash"},
	"makefile.in":    {"c", "bash"},
	"meson.build":    {"c", "cpp"},
	"gnumakefile":    {"bash"},
	"makefile":       {"bash"},
	// Rust
	"cargo.toml": {"rust"},
	// PHP
	"composer.json": {"php"},
	// Python build systems (Bazel/SCons/Waf/Snakemake — Python source)
	"snakefile":       {"python"},
	"sconstruct":      {"python"},
	"sconscript":      {"python"},
	"wscript":         {"python"},
	"build.bazel":     {"python"},
	"workspace.bazel": {"python"},
	"module.bazel":    {"python"},
	// Linux packaging (pure bash)
	"pkgbuild": {"bash"},
	"apkbuild": {"bash"},
	// Container orchestration (compose security rules)
	"docker-compose.yml":  {"docker"},
	"docker-compose.yaml": {"docker"},
	"compose.yml":         {"docker"},
	"compose.yaml":        {"docker"},
	"earthfile":           {"docker"},
}

// canonicalLang resolves a metadata label to its canonical ecosystem key.
func canonicalLang(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	if c, ok := languageAliases[label]; ok {
		return c
	}
	return label
}

// knownLanguage reports whether we have an extension/filename mapping for the
// canonical form of a label (so the filter only skips confidently-inapplicable
// rules and keeps anything it does not understand).
func knownLanguage(label string) bool {
	c := canonicalLang(label)
	if _, ok := languageExtensions[c]; ok {
		return true
	}
	for _, labels := range languageFilenames {
		if slices.Contains(labels, c) {
			return true
		}
	}
	return false
}

var (
	languagesKeyRe = regexp.MustCompile(`(?s)"languages"\s*:\s*\[(.*?)\]`)
	quotedTokenRe  = regexp.MustCompile(`"([^"]*)"`)
)

// ruleLanguages extracts the declared metadata.languages from a rego module
// source. The second return is false when the module has no languages key at all
// (helpers, libraries, or malformed rules) — treated as universal by the caller.
func ruleLanguages(src string) ([]string, bool) {
	m := languagesKeyRe.FindStringSubmatch(src)
	if m == nil {
		return nil, false
	}
	toks := quotedTokenRe.FindAllStringSubmatch(m[1], -1)
	langs := make([]string, 0, len(toks))
	for _, t := range toks {
		v := strings.ToLower(strings.TrimSpace(t[1]))
		if v != "" {
			langs = append(langs, v)
		}
	}
	return langs, true
}

// presentLanguages returns the set of canonical ecosystems present in the scanned
// file set, by matching file extensions (suffix) and special filenames.
func presentLanguages(fileSet map[string]bool) map[string]bool {
	present := map[string]bool{}
	for path := range fileSet {
		base := strings.ToLower(filepath.Base(path))
		if labels, ok := languageFilenames[base]; ok {
			for _, l := range labels {
				present[canonicalLang(l)] = true
			}
		}
		for sub, labels := range languageBasenameSubstrings {
			if strings.Contains(base, sub) {
				for _, l := range labels {
					present[canonicalLang(l)] = true
				}
			}
		}
		for canon, exts := range languageExtensions {
			for _, ext := range exts {
				if strings.HasSuffix(base, ext) {
					present[canon] = true
					break
				}
			}
		}
	}
	return present
}

// keepModuleForLanguages decides whether a single rego module survives the
// language pre-filter. Universal/unknown rules are always kept; a rule is dropped
// only when every declared language is known AND absent from the repository.
func keepModuleForLanguages(src string, present map[string]bool) bool {
	langs, found := ruleLanguages(src)
	if !found || len(langs) == 0 {
		return true // no/empty languages → universal (e.g. secrets)
	}
	for _, l := range langs {
		if l == "generic" || l == "all" || l == "any" {
			return true
		}
		if !knownLanguage(l) {
			return true // fail-open on anything we don't model
		}
		if present[canonicalLang(l)] {
			return true
		}
	}
	return false
}

// filterModulesByLanguage drops rule modules whose declared languages are all
// absent from the scanned repository. Shared (non-rule) modules are passed
// through untouched.
func filterModulesByLanguage(modules map[string]string, fileSet map[string]bool) map[string]string {
	present := presentLanguages(fileSet)
	out := make(map[string]string, len(modules))
	for name, src := range modules {
		// Only rule packages are language-scoped; helpers/libraries stay.
		if strings.Contains(src, "package vulnetix.rules.") {
			if !keepModuleForLanguages(src, present) {
				continue
			}
		}
		out[name] = src
	}
	return out
}
