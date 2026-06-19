package sast

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var testIDKeyRe = regexp.MustCompile(`"id"\s*:\s*"([^"]+)"`)

func testRuleID(src string) string {
	m := testIDKeyRe.FindStringSubmatch(src)
	if m == nil {
		return ""
	}
	return m[1]
}

// For every language, a repo containing that language must KEEP all of that
// language's rules — this is the detection-completeness guarantee (a gap here
// would wrongly skip a present language's rules and miss findings). Pure string
// work over the real ruleset, so it's fast.
func TestLanguageFilterKeepsEachLanguagesRules(t *testing.T) {
	all, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)

	// canonical ecosystem → a representative file that must mark it present
	samples := map[string]string{
		"python":     "x.py",
		"javascript": "x.ts", // node/typescript all canonicalise here
		"java":       "X.java",
		"kotlin":     "X.kt",
		"android":    "x.aidl",
		"go":         "x.go",
		"c":          "x.c",
		"cpp":        "x.cpp",
		"php":        "x.php",
		"ruby":       "x.rb",
		"csharp":     "x.cs",
		"rust":       "x.rs",
		"swift":      "x.swift",
		"terraform":  "x.tf",
		"docker":     "Dockerfile",
		"bash":       "x.sh",
		"html":       "x.html",
		"sql":        "x.sql",
		"graphql":    "x.graphql",
	}

	// Precompute each rule module's canonical language set.
	type ruleInfo struct {
		name  string
		canon map[string]bool
		uni   bool // universal (empty/missing/generic/unknown)
	}
	var rules []ruleInfo
	for name, src := range all {
		if !strings.Contains(src, "package vulnetix.rules.") {
			continue
		}
		langs, found := ruleLanguages(src)
		info := ruleInfo{name: name, canon: map[string]bool{}}
		if !found || len(langs) == 0 {
			info.uni = true
		}
		for _, l := range langs {
			if l == "generic" || !knownLanguage(l) {
				info.uni = true
			}
			info.canon[canonicalLang(l)] = true
		}
		rules = append(rules, info)
	}

	for canon, file := range samples {
		t.Run(canon, func(t *testing.T) {
			out := filterModulesByLanguage(all, map[string]bool{file: true})
			missing := 0
			for _, r := range rules {
				if r.uni || r.canon[canon] {
					require.Containsf(t, out, r.name, "rule %s (langs %v) must be kept when %s present (%s)", r.name, r.canon, canon, file)
				}
				if _, kept := out[r.name]; !kept {
					missing++
				}
			}
			// Sanity: a single-language repo must drop SOME rules (filter isn't a no-op).
			require.Positivef(t, missing, "%s: expected some inapplicable rules to be dropped", canon)
		})
	}
}

// The core functional claim: filtering a pure-Go repo must not drop any finding
// that comes from a rule applicable to Go — only inapplicable cross-language
// noise may disappear. Run against the full embedded ruleset.
func TestLanguageFilterPreservesApplicableFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates the full embedded ruleset twice")
	}
	all, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)

	srcByID := map[string]string{}
	for _, src := range all {
		if id := testRuleID(src); id != "" {
			srcByID[id] = src
		}
	}

	dir := t.TempDir()
	// Kitchen-sink Go file with patterns many rules look for, plus go.mod so Go
	// is unambiguously the present language.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import ("crypto/md5"; "os/exec"; "math/rand")
func vuln(userInput, cmd, id, path string) {
	password := "hunter2hunter2hunter2"   // hardcoded secret
	apiKey := "AKIAIOSFODNN7EXAMPLE"      // aws key
	_ = md5.New()                          // weak crypto
	token := rand.Int()                    // weak prng token
	_ = exec.Command("/bin/sh", "-c", cmd) // command injection
	query := "SELECT * FROM users WHERE id = " + id
	_ = password; _ = apiKey; _ = token; _ = query; _ = userInput; _ = path
}
func main(){}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\ngo 1.25\n"), 0o644))

	run := func(noFilter string) *SASTReport {
		t.Setenv("VULNETIX_SAST_NO_LANG_FILTER", noFilter)
		rep, err := NewEngine(all, dir).Evaluate(EvalOptions{MaxDepth: 5})
		require.NoError(t, err)
		return rep
	}
	full := run("1")    // filter disabled
	filtered := run("") // filter enabled

	goPresent := map[string]bool{"go": true}
	filtSet := map[string]bool{}
	for _, f := range filtered.Findings {
		filtSet[f.RuleID+"|"+f.ArtifactURI+"|"+f.Snippet] = true
	}

	var lostApplicable []string
	for _, f := range full.Findings {
		src, ok := srcByID[f.RuleID]
		if !ok {
			continue
		}
		if !keepModuleForLanguages(src, goPresent) {
			continue // rule not applicable to Go — fine to drop
		}
		key := f.RuleID + "|" + f.ArtifactURI + "|" + f.Snippet
		if !filtSet[key] {
			lostApplicable = append(lostApplicable, f.RuleID)
		}
	}

	t.Logf("full=%d filtered=%d (dropped %d inapplicable)", len(full.Findings), len(filtered.Findings), len(full.Findings)-len(filtered.Findings))
	require.Empty(t, lostApplicable, "filter dropped findings from Go-applicable rules: %v", lostApplicable)
	require.LessOrEqual(t, len(filtered.Findings), len(full.Findings), "filter must not add findings")
	require.Positive(t, len(filtered.Findings), "fixture should still produce Go findings after filtering")
}

func TestRuleLanguages(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantLangs []string
		wantFound bool
	}{
		{"single", `metadata := {"id":"X","languages": ["go"]}`, []string{"go"}, true},
		{"multi", `"languages": ["node", "javascript", "typescript"]`, []string{"node", "javascript", "typescript"}, true},
		{"empty", `"languages": []`, []string{}, true},
		{"missing", `metadata := {"id":"X","severity":"low"}`, nil, false},
		{"multiline", "\"languages\": [\n  \"python\",\n  \"java\"\n]", []string{"python", "java"}, true},
		{"uppercase-normalised", `"languages": ["Go", "C++"]`, []string{"go", "c++"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			langs, found := ruleLanguages(tc.src)
			require.Equal(t, tc.wantFound, found)
			require.Equal(t, tc.wantLangs, langs)
		})
	}
}

func TestCanonicalLang(t *testing.T) {
	require.Equal(t, "javascript", canonicalLang("node"))
	require.Equal(t, "javascript", canonicalLang("typescript"))
	require.Equal(t, "javascript", canonicalLang("JavaScript"))
	require.Equal(t, "bash", canonicalLang("shell"))
	require.Equal(t, "go", canonicalLang("golang"))
	require.Equal(t, "cpp", canonicalLang("c++"))
	require.Equal(t, "csharp", canonicalLang("dotnet"))
	require.Equal(t, "elixir", canonicalLang("elixir")) // unknown passes through
}

func TestPresentLanguages(t *testing.T) {
	cases := []struct {
		name string
		file string
		want []string // canonical labels expected present
	}{
		{"go source", "main.go", []string{"go"}},
		{"typescript → js ecosystem", "src/app.ts", []string{"javascript"}},
		{"vue → js ecosystem", "components/App.vue", []string{"javascript"}},
		{"mjs → js ecosystem", "x.mjs", []string{"javascript"}},
		{"dts → js ecosystem", "types/x.d.ts", []string{"javascript"}},
		{"dockerfile exact", "Dockerfile", []string{"docker"}},
		{"containerfile ext", "service.containerfile", []string{"docker"}},
		{"dockerfile suffix variant", "Containerfile.postgres", []string{"docker"}},
		{"dockerfile prod variant", "Dockerfile.prod", []string{"docker"}},
		{"header is c and cpp", "lib/foo.h", []string{"c", "cpp"}},
		{"gql is graphql and sql", "schema.gql", []string{"graphql", "sql"}},
		{"erb is ruby and html", "views/index.erb", []string{"ruby", "html"}},
		{"go.mod filename", "go.mod", []string{"go"}},
		{"android manifest filename", "app/src/AndroidManifest.xml", []string{"android"}},
		{"cmake → c and cpp", "CMakeLists.txt", []string{"c", "cpp"}},
		{"kt → kotlin and android", "Main.kt", []string{"kotlin", "android"}},
		{"objc impl is c and cpp", "ViewController.m", []string{"c", "cpp"}},
		{"starlark is python", "BUILD.bzl", []string{"python"}},
		{"scala is jvm/java", "Main.scala", []string{"java"}},
		{"dataform sqlx is sql", "models/users.sqlx", []string{"sql"}},
		{"composer.json is php", "composer.json", []string{"php"}},
		{"compose file is docker", "docker-compose.yml", []string{"docker"}},
		{"pkgbuild is bash", "PKGBUILD", []string{"bash"}},
		{"fastfile is ruby", "fastlane/Fastfile", []string{"ruby"}},
		{"asciidoc is html", "guide.adoc", []string{"html"}},
		{"non-source has no language", "README.md", nil},
		{"package.json deliberately not a language signal", "package.json", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present := presentLanguages(map[string]bool{tc.file: true})
			for _, w := range tc.want {
				require.Truef(t, present[w], "expected %q present for %s; got %v", w, tc.file, present)
			}
			if tc.want == nil {
				require.Emptyf(t, present, "expected no languages for %s; got %v", tc.file, present)
			}
		})
	}
}

func TestKeepModuleForLanguages(t *testing.T) {
	goPresent := map[string]bool{"go": true}
	mod := func(langs string) string { return `metadata := {"id":"X",` + langs + `}` }

	require.True(t, keepModuleForLanguages(mod(`"languages":["go"]`), goPresent), "present language kept")
	require.False(t, keepModuleForLanguages(mod(`"languages":["python"]`), goPresent), "absent language skipped")
	require.True(t, keepModuleForLanguages(mod(`"languages":[]`), goPresent), "empty/universal kept")
	require.True(t, keepModuleForLanguages(mod(`"languages":["generic"]`), map[string]bool{}), "generic kept")
	require.True(t, keepModuleForLanguages(mod(`"languages":["cobol"]`), goPresent), "unknown language fail-open kept")
	require.True(t, keepModuleForLanguages(mod(`"languages":["java","go"]`), goPresent), "any-present kept")
	require.False(t, keepModuleForLanguages(mod(`"languages":["java","python"]`), goPresent), "all-absent skipped")
	require.True(t, keepModuleForLanguages(`metadata := {"id":"X"}`, goPresent), "no languages key kept")
	// node-family resolves through the alias to the js ecosystem
	require.True(t, keepModuleForLanguages(mod(`"languages":["node"]`), map[string]bool{"javascript": true}), "node alias kept when js present")
}

func TestFilterModulesByLanguage(t *testing.T) {
	modules := map[string]string{
		"helpers.rego":  "package vulnetix.helpers\n", // shared, always kept
		"go_rule.rego":  `package vulnetix.rules.r1` + "\n" + `metadata := {"id":"R1","languages":["go"]}`,
		"py_rule.rego":  `package vulnetix.rules.r2` + "\n" + `metadata := {"id":"R2","languages":["python"]}`,
		"sec_rule.rego": `package vulnetix.rules.r3` + "\n" + `metadata := {"id":"R3","languages":[]}`, // universal secrets
		"js_rule.rego":  `package vulnetix.rules.r4` + "\n" + `metadata := {"id":"R4","languages":["typescript"]}`,
	}
	// A pure-Go repo.
	out := filterModulesByLanguage(modules, map[string]bool{"main.go": true})
	require.Contains(t, out, "helpers.rego", "shared module kept")
	require.Contains(t, out, "go_rule.rego", "go rule kept")
	require.Contains(t, out, "sec_rule.rego", "universal rule kept")
	require.NotContains(t, out, "py_rule.rego", "python rule dropped on go repo")
	require.NotContains(t, out, "js_rule.rego", "typescript rule dropped on go repo")

	// Add a .ts file → js rule must survive.
	out2 := filterModulesByLanguage(modules, map[string]bool{"main.go": true, "app.ts": true})
	require.Contains(t, out2, "js_rule.rego", "typescript rule kept when .ts present")
	require.NotContains(t, out2, "py_rule.rego", "python still dropped")
}
