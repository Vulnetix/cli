package testsuite

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// Config is a test-runner configuration file detected on disk. It is metadata
// only — the raw body is never carried off the host (test configs are
// low-sensitivity but there is no need to archive them). Mirrors the shape of
// the SCA manifest metadata so the backend can persist it the same way.
type Config struct {
	Path        string `json:"path"`
	Framework   string `json:"framework"`
	Language    string `json:"language,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Size        int64  `json:"size,omitempty"`
}

// Active is the corroborating evidence a repo scan produced: the set of test
// frameworks with a config file and/or a declared dependency, plus the config
// files themselves and a framework→evidence map used to annotate findings.
type Active struct {
	Configs   []Config
	Present   map[string]bool   // framework → true
	Evidence  map[string]string // framework → human evidence string
	AnyConfig bool
}

// walkSkipDirs are never descended: VCS, dependency installs, build output.
var walkSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"venv": true, "dist": true, "build": true, "target": true,
	".gradle": true, ".idea": true, ".vscode": true, "__pycache__": true,
	".tox": true, ".nox": true, "bin": true, "obj": true,
}

// maxWalkDepth bounds how deep the config/manifest walk descends from the root.
// Test-runner config and manifests live near the top of a repo; a deep cap keeps
// the extra pass cheap on large trees.
const maxWalkDepth = 8

// Scan walks rootPath for test-runner configuration files and test frameworks
// declared in package-manager manifests, returning the combined corroborating
// evidence. It is self-contained (does not depend on the SCA pass having run),
// so `vulnetix sast` in isolation still gets config-file evidence.
func Scan(rootPath string) Active {
	act := Active{Present: map[string]bool{}, Evidence: map[string]string{}}
	if rootPath == "" {
		rootPath = "."
	}
	rootPath = filepath.Clean(rootPath)

	_ = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped, not fatal
		}
		if d.IsDir() {
			name := d.Name()
			if path != rootPath && (walkSkipDirs[name] || strings.HasPrefix(name, ".") && name != ".github") {
				return fs.SkipDir
			}
			if depthFrom(rootPath, path) > maxWalkDepth {
				return fs.SkipDir
			}
			return nil
		}

		base := strings.ToLower(d.Name())
		rel := relFromRoot(rootPath, path)

		// Config-file detection.
		if hit := matchConfigFile(path, base); hit != nil {
			hit.Path = rel
			act.Configs = append(act.Configs, *hit)
			act.AnyConfig = true
			act.Present[hit.Framework] = true
			if _, ok := act.Evidence[hit.Framework]; !ok {
				act.Evidence[hit.Framework] = "config:" + rel
			}
		}

		// Manifest declared-dependency detection.
		if isManifestBase(base) {
			if body, ok := readCapped(path, manifestReadBudget); ok {
				for fw, ev := range declaredFrameworks(rel, body) {
					act.Present[fw] = true
					if _, ok := act.Evidence[fw]; !ok {
						act.Evidence[fw] = ev
					}
				}
			}
		}
		return nil
	})
	return act
}

// matchConfigFile returns a Config (framework/language/hash/size, no path) when
// the file matches a config rule, else nil. Reads content only when a rule for
// this basename needs a marker.
func matchConfigFile(path, base string) *Config {
	var lowerContent string
	if configNeedsContent(base) {
		if body, ok := readCapped(path, configReadBudget); ok {
			lowerContent = strings.ToLower(body)
		}
	}
	for _, r := range configRules {
		if !r.matchConfig(base, lowerContent) {
			continue
		}
		sum, size := hashFile(path)
		return &Config{
			Framework:   r.framework,
			Language:    r.language,
			ContentType: contentTypeForExt(path),
			SHA256:      sum,
			Size:        size,
		}
	}
	return nil
}

// Annotate stamps each SAST finding with test-suite attribution derived from its
// file path, upgrading confidence and attaching corroborating evidence when the
// repo scan found a matching config file or declared dependency. Returns the
// number of findings marked as test code.
func Annotate(findings []sast.Finding, act Active) int {
	marked := 0
	for i := range findings {
		det := DetectPath(findings[i].ArtifactURI)
		if !det.IsTestSuite {
			continue
		}
		marked++

		evidence := []string{"path:" + det.MatchedPattern}

		// Resolve the framework: prefer the path's guess, but if the path is
		// ambiguous and exactly one framework is active in the repo, adopt it.
		fw := det.Framework
		if fw == "" && len(act.Present) == 1 {
			for f := range act.Present {
				fw = f
			}
		}

		// Corroboration: a present config/dep for this framework (or, when the
		// path framework is ambiguous, any active framework) elevates confidence
		// to confirmed and contributes evidence.
		corroborated := false
		if fw != "" && act.Present[fw] {
			corroborated = true
			if ev := act.Evidence[fw]; ev != "" {
				evidence = append(evidence, ev)
			}
		} else if det.Framework == "" && act.AnyConfig {
			corroborated = true
			for f, ev := range act.Evidence {
				evidence = append(evidence, ev)
				if fw == "" {
					fw = f
				}
			}
		}

		confidence := det.Confidence
		if corroborated && confidenceScore(confidence) >= confidenceScore(ConfidenceMedium) {
			confidence = ConfidenceConfirmed
		}

		findings[i].IsTestSuite = true
		findings[i].TestFramework = fw
		findings[i].TestLanguage = det.Language
		findings[i].TestConfidence = confidence
		findings[i].TestMatchedPattern = det.MatchedPattern
		findings[i].TestEvidence = evidence
	}
	return marked
}

// ── helpers ────────────────────────────────────────────────────────────────

func isManifestBase(base string) bool {
	switch base {
	case "package.json", "pyproject.toml", "setup.cfg", "requirements-dev.txt",
		"requirements_test.txt", "gemfile", "composer.json", "cargo.toml",
		"pom.xml", "build.gradle", "build.gradle.kts", "build.sbt", "go.mod",
		"pubspec.yaml", "mix.exs", "package.swift", "podfile", "project.clj",
		"deps.edn", "description", "rebar.config", "stack.yaml", "shard.yml":
		return true
	}
	return strings.HasSuffix(base, ".csproj") ||
		strings.HasSuffix(base, ".fsproj") ||
		strings.HasSuffix(base, ".cabal") ||
		(strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"))
}

func readCapped(path string, budget int) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > int64(budget) {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func hashFile(path string) (string, int64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data))
}

func relFromRoot(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

func depthFrom(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	if rel == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/") + 1
}
