package cmd

// Per-package manifest detectors for `malscan`: the detect.Detect pattern /
// shell-obfuscation engine, ioc.ExtractIOCs, and the badhash known-bad
// artifact-hash blocklist, run over the manifests/install-scripts discovered
// inside each resolved ecosystem target. The STIX IOC filesystem scan
// (iocscan) lives in malscan.go; this file is the manifest-level half of the
// "full engine".

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vulnetix/malscan-engine/badhash"
	"github.com/vulnetix/malscan-engine/detect"
	"github.com/vulnetix/malscan-engine/ioc"
	"github.com/vulnetix/malscan-engine/iocscan"

	"github.com/vulnetix/cli/v3/internal/ecosystems"
)

// manifestSpec describes how to find and read one ecosystem's package manifests.
type manifestSpec struct {
	primary    []string // base filenames read into PkgbuildContent
	install    []string // base filenames concatenated into InstallScriptContent
	installExt string   // suffix match for install files (e.g. ".install")
	gemspec    bool     // match *.gemspec as the primary manifest
	npmScripts bool     // parse package.json scripts.* into InstallScriptContent
}

// manifestSpecFor returns the manifest discovery spec for an ecosystem (keyed by
// the human ecosystem name, so php — whose engine slug is "generic" — is
// distinguishable). A zero spec means "no manifest detectors" (iocscan still
// covers the target's files).
func manifestSpecFor(ecosystem string) (manifestSpec, bool) {
	switch ecosystem {
	case "javascript":
		return manifestSpec{primary: []string{"package.json"}, npmScripts: true}, true
	case "python":
		return manifestSpec{primary: []string{"setup.py", "pyproject.toml", "PKG-INFO"}}, true
	case "rust":
		return manifestSpec{primary: []string{"Cargo.toml"}, install: []string{"build.rs"}}, true
	case "ruby":
		return manifestSpec{gemspec: true, install: []string{"extconf.rb"}}, true
	case "php":
		return manifestSpec{primary: []string{"composer.json"}}, true
	default:
		return manifestSpec{}, false
	}
}

// pkgManifest is one discovered package's manifest + install files.
type pkgManifest struct {
	dir     string
	primary string // absolute path of the primary manifest
}

// scanTargetManifests discovers up to `budget` package manifests under target,
// runs the per-package detectors on each, and folds the results into res.
// Returns how many packages it processed (to debit the shared budget).
func scanTargetManifests(target ecosystems.Target, caps map[string]bool, root string, res *malscanResult, malicious map[string]bool, budget int) int {
	spec, ok := manifestSpecFor(target.Ecosystem)
	if !ok {
		return 0
	}
	pkgs := discoverManifests(target.Path, spec, budget)
	badSet := badhash.New()
	// Fold in the TweetFeed base feed's file-hash IOCs (SHA-256/MD5). Cache-backed,
	// so it adds no network cost on the hot path; `--fetch-definitions` keeps them
	// fresh. Non-fatal: a fetch failure simply leaves the embedded set in place.
	if hs, _, err := (&iocscan.FeedLoader{}).TweetFeedHashes(false); err == nil {
		badSet.AddAll(hs)
	}
	for _, p := range pkgs {
		if processPackageManifest(p, spec, caps, target, root, res, malicious, badSet) {
			// processed
		}
	}
	return len(pkgs)
}

// discoverManifests walks a target collecting package directories that hold a
// primary manifest, stopping once `budget` are found.
func discoverManifests(targetPath string, spec manifestSpec, budget int) []pkgManifest {
	var out []pkgManifest
	skip := nameSetCmd(ecosystems.ScanSkipDirs())
	_ = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != targetPath && skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(out) >= budget {
			return filepath.SkipAll
		}
		if isPrimaryManifest(d.Name(), spec) {
			out = append(out, pkgManifest{dir: filepath.Dir(path), primary: path})
		}
		return nil
	})
	return out
}

func isPrimaryManifest(name string, spec manifestSpec) bool {
	if spec.gemspec && strings.HasSuffix(name, ".gemspec") {
		return true
	}
	for _, p := range spec.primary {
		if name == p {
			return true
		}
	}
	return false
}

// processPackageManifest builds a detect.PackageContext from one package's
// manifest + install files, runs detect.Detect + ioc.ExtractIOCs + badhash, and
// records the findings/IOCs. Returns true when the package was analysed.
func processPackageManifest(p pkgManifest, spec manifestSpec, caps map[string]bool, target ecosystems.Target, root string, res *malscanResult, malicious map[string]bool, badSet *badhash.Set) bool {
	primaryContent := readCapped(p.primary, malscanManifestMaxBytes)
	if primaryContent == "" {
		return false
	}
	rel := relToRoot(root, p.primary)
	name := filepath.Base(p.dir)

	var installContent strings.Builder
	if spec.npmScripts {
		installContent.WriteString(npmInstallScripts(primaryContent))
	}
	for _, inst := range spec.install {
		if c := readCapped(filepath.Join(p.dir, inst), malscanManifestMaxBytes); c != "" {
			installContent.WriteString("\n")
			installContent.WriteString(c)
		}
	}
	if spec.installExt != "" {
		entries, _ := os.ReadDir(p.dir)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), spec.installExt) {
				if c := readCapped(filepath.Join(p.dir, e.Name()), malscanManifestMaxBytes); c != "" {
					installContent.WriteString("\n")
					installContent.WriteString(c)
				}
			}
		}
	}

	ctx := &detect.PackageContext{
		Name:                 name,
		Ecosystem:            target.EngineSlug,
		Capabilities:         caps,
		PkgbuildContent:      primaryContent,
		InstallScriptContent: installContent.String(),
	}
	findings := detect.Detect(ctx)

	// badhash over declared/candidate hashes (engine's intended use — not a
	// full-tree hash). A hit is factual evidence.
	repo := &ioc.RepoData{PkgbuildContent: primaryContent, InstallScripts: installContent.String()}
	for _, h := range ioc.CandidateHashes(repo) {
		if badSet.Has(h) {
			findings = append(findings, detect.EvidenceFinding(
				detect.KnownBadHashID, "badhash", detect.DefaultMalwareCWE,
				"artifact hash matches a known-bad malware hash", h))
		}
	}

	verdict := detect.CombinedVerdict(findings)
	anyEvidence := false
	for _, f := range findings {
		mf := detectFindingToMalscan(f, target.Ecosystem, rel, primaryContent)
		res.Findings = append(res.Findings, mf)
		if f.Class == detect.ClassEvidence {
			anyEvidence = true
		}
	}

	// Only emit extracted IOCs + a manifest sample when the package is judged
	// malicious (evidence or a combined-verdict path) — otherwise extracted
	// indicators are mere observations, not malware IOCs.
	if anyEvidence || verdict.Malicious {
		malicious[malwareLabel(target.Ecosystem, rel)] = true
		sample := &malscanSample{Name: filepath.Base(p.primary), Content: []byte(primaryContent), SHA256: sha256Hex([]byte(primaryContent))}
		for _, x := range ioc.ExtractIOCs(repo) {
			res.IOCs = append(res.IOCs, malscanIOC{
				Type:      x.Type,
				Value:     x.Value,
				Ecosystem: pickEcosystem(x.Ecosystem, target.EngineSlug),
				FilePath:  rel,
				RuleID:    "MALSCAN-DETECT",
				Severity:  "high",
				Sample:    sample,
			})
		}
		for _, h := range ioc.CandidateHashes(repo) {
			if badSet.Has(h) {
				res.IOCs = append(res.IOCs, malscanIOC{
					Type: "file-hash", Value: h, Ecosystem: target.EngineSlug,
					FilePath: rel, RuleID: detect.KnownBadHashID, Severity: "critical", Sample: sample,
				})
			}
		}
	}
	return true
}

// detectFindingToMalscan converts an engine detect.Finding into the unified
// internal finding shape. When the matched line can be located in the manifest
// content, an accurate line number + snippet is attached; otherwise (e.g. a
// synthesised npm install-script line) the matched code is carried in the
// message so the evidence is never lost from the SARIF.
func detectFindingToMalscan(f detect.Finding, ecosystem, file, content string) malscanFinding {
	sev, level := classSeverity(f.Class)
	line := findLineInContent(content, f.MatchedLine)
	message := f.Description
	if line == 0 && f.MatchedLine != "" {
		message = f.Description + "\nMatched: " + f.MatchedLine
	}
	return malscanFinding{
		RuleID:      f.ID,
		Title:       f.Category,
		Description: f.Description,
		Message:     message,
		Severity:    sev,
		Level:       level,
		Ecosystem:   ecosystem,
		File:        file,
		StartLine:   line,
		EndLine:     line,
		Snippet:     f.MatchedLine,
		CWEs:        cweNums(f.CWE),
		Class:       string(f.Class),
		Category:    f.Category,
		Tags:        []string{"malware", string(f.Class), f.Category},
		Fingerprint: fingerprint(f.ID, file, f.MatchedLine),
	}
}

// findLineInContent returns the 1-based line number of the first line in content
// containing the (trimmed) matched text, or 0 when not found.
func findLineInContent(content, matched string) int {
	matched = strings.TrimSpace(matched)
	if matched == "" || content == "" {
		return 0
	}
	for i, line := range strings.Split(content, "\n") {
		if strings.Contains(line, matched) {
			return i + 1
		}
	}
	return 0
}

// classSeverity maps a detect.Class to (severity, SARIF level).
func classSeverity(c detect.Class) (string, string) {
	switch c {
	case detect.ClassEvidence:
		return "critical", "error"
	case detect.ClassTrigger:
		return "medium", "warning"
	default: // context
		return "low", "note"
	}
}

// npmInstallScripts extracts the install-lifecycle scripts from a package.json
// body so the shell/pattern detectors run over the actual install hooks.
func npmInstallScripts(pkgJSON string) string {
	var doc struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal([]byte(pkgJSON), &doc); err != nil {
		return ""
	}
	var b strings.Builder
	for _, k := range []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall", "prepare", "prepublish"} {
		if v := doc.Scripts[k]; v != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	return b.String()
}

// evidenceDescription renders a human-readable description for an iocscan hit.
func evidenceDescription(ev iocscan.Evidence) string {
	loc := ev.RelPath
	if loc == "" {
		loc = ev.FilePath
	}
	if ev.Indicator != nil && ev.Indicator.Name != "" {
		return fmt.Sprintf("%s — known-bad %s %q referenced in %s", ev.Indicator.Name, ev.IndicatorType, ev.IndicatorValue, loc)
	}
	return fmt.Sprintf("file references known-bad %s IOC %q", ev.IndicatorType, ev.IndicatorValue)
}

// malscanSnippet builds the code-sample text for an iocscan hit: the matched
// line bracketed by its context lines.
func malscanSnippet(ev iocscan.Evidence) string {
	if ev.MatchedLine == "" {
		return ev.IndicatorValue
	}
	var lines []string
	lines = append(lines, ev.ContextBefore...)
	lines = append(lines, ev.MatchedLine)
	lines = append(lines, ev.ContextAfter...)
	return strings.Join(lines, "\n")
}

// indicatorRefs collects STIX external-reference URLs for an evidence hit.
func indicatorRefs(ev iocscan.Evidence) []string {
	if ev.Indicator == nil {
		return nil
	}
	var out []string
	for _, r := range ev.Indicator.ExternalRefs {
		if r.URL != "" {
			out = append(out, r.URL)
		}
	}
	return out
}

func pickEcosystem(iocEco, fallback string) string {
	if iocEco != "" {
		return iocEco
	}
	return fallback
}

func readCapped(path string, max int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > max {
		data = data[:max]
	}
	return string(data)
}

func nameSetCmd(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// small runtime/time shims so malscan.go stays import-light.
func goos() string       { return runtime.GOOS }
func goarch() string     { return runtime.GOARCH }
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
