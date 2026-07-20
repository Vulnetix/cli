// Package testsuite detects whether a source-code finding lives in a project's
// test suite, and identifies the testing framework responsible.
//
// Unlike a pure backend heuristic that only sees a file path, this runs inside
// the repository during a scan, so it corroborates the path-name guess with two
// stronger, repo-local signals: test-runner configuration files present on disk
// (jest.config.js, pytest.ini, phpunit.xml, …) and test frameworks declared as
// dev-dependencies in package-manager manifests. A path match plus a present
// config or a declared dependency is a confirmed attribution, not a coincidence.
//
// detect.go carries the path-name heuristic. It is an exhaustive, ordered table
// of patterns spanning every language in the Wikipedia "List of unit testing
// frameworks", ported from and extended beyond the backend's TypeScript
// TEST_PATTERNS. Order matters: more specific patterns come first, and the best
// (highest-confidence, framework-naming) match wins.
package testsuite

import (
	"regexp"
	"strings"
)

// Confidence levels for a path-name match. `confirmed` is never produced by the
// path heuristic alone — attribute.go elevates a high/medium path match to
// confirmed when a config file or declared dependency corroborates it.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceHigh      = "high"
	ConfidenceMedium    = "medium"
	ConfidenceLow       = "low"
)

// Detection is the result of classifying a single file path.
type Detection struct {
	IsTestSuite    bool     `json:"isTestSuite"`
	Framework      string   `json:"testFramework,omitempty"`
	Language       string   `json:"testLanguage,omitempty"`
	Confidence     string   `json:"testConfidence,omitempty"`
	MatchedPattern string   `json:"testMatchedPattern,omitempty"`
	Evidence       []string `json:"testEvidence,omitempty"`
}

// testPattern is one entry in the ordered classification table.
type testPattern struct {
	re         *regexp.Regexp
	framework  string // "" when the path is a test but the framework is ambiguous
	language   string
	confidence string
	desc       string
}

// pat compiles one pattern. Patterns are case-insensitive and matched against a
// forward-slash-normalized path.
func pat(expr, framework, language, confidence, desc string) testPattern {
	return testPattern{
		re:         regexp.MustCompile("(?i)" + expr),
		framework:  framework,
		language:   language,
		confidence: confidence,
		desc:       desc,
	}
}

// testPatterns is the ordered classification table. Ordering rules:
//   - File-name patterns before directory patterns (a name is more specific).
//   - Language-specific patterns before generic ones, so e.g. Go's `_test.go`
//     is attributed to `go test` rather than a bare "test directory".
//   - Generic directory fallbacks (test/, tests/, spec/) come last.
//
// Framework names are the canonical lowercase spellings the backend already
// uses (jest, pytest, junit, go test, rspec, xctest, xunit, phpunit, cargo
// test), extended with the additional languages/frameworks below.
var testPatterns = []testPattern{
	// ── JavaScript / TypeScript ────────────────────────────────────────────
	pat(`\.test\.(js|ts|jsx|tsx|mjs|cjs)$`, "jest", "javascript", ConfidenceHigh, "Jest/Vitest test file (*.test.*)"),
	pat(`\.spec\.(js|ts|jsx|tsx|mjs|cjs)$`, "jasmine", "javascript", ConfidenceHigh, "Jasmine/Mocha spec file (*.spec.*)"),
	pat(`\.e2e-spec\.(js|ts)$`, "playwright", "javascript", ConfidenceHigh, "Playwright/Protractor E2E spec"),
	pat(`\.cy\.(js|ts|jsx|tsx)$`, "cypress", "javascript", ConfidenceHigh, "Cypress test file (*.cy.*)"),
	pat(`\.stories\.(js|ts|jsx|tsx|mdx)$`, "storybook", "javascript", ConfidenceMedium, "Storybook story"),
	pat(`__tests__/`, "jest", "javascript", ConfidenceHigh, "Jest __tests__ directory"),
	pat(`__mocks__/`, "jest", "javascript", ConfidenceHigh, "Jest __mocks__ directory"),
	pat(`/cypress/`, "cypress", "javascript", ConfidenceHigh, "Cypress directory"),
	pat(`(^|/)e2e/`, "playwright", "javascript", ConfidenceMedium, "E2E test directory"),

	// ── Python ─────────────────────────────────────────────────────────────
	pat(`(^|/)test_[^/]+\.py$`, "pytest", "python", ConfidenceHigh, "pytest/unittest test file (test_*.py)"),
	pat(`_test\.py$`, "pytest", "python", ConfidenceHigh, "pytest test file (*_test.py)"),
	pat(`conftest\.py$`, "pytest", "python", ConfidenceHigh, "pytest conftest.py"),
	pat(`(^|/)tests?/.*\.py$`, "pytest", "python", ConfidenceHigh, "Python test directory"),

	// ── Kotlin (before Java src/test/ so .kt names win) ────────────────────
	pat(`Spec\.kt$`, "kotest", "kotlin", ConfidenceHigh, "Kotest specification"),
	pat(`Tests?\.kt$`, "junit", "kotlin", ConfidenceHigh, "Kotlin JUnit test"),

	// ── Groovy / Spock ─────────────────────────────────────────────────────
	pat(`Spec\.groovy$`, "spock", "groovy", ConfidenceHigh, "Spock specification"),
	pat(`Test\.groovy$`, "junit", "groovy", ConfidenceHigh, "Groovy JUnit test"),

	// ── Java ───────────────────────────────────────────────────────────────
	pat(`Tests?\.java$`, "junit", "java", ConfidenceHigh, "JUnit test file"),
	pat(`TestCase\.java$`, "junit", "java", ConfidenceHigh, "JUnit TestCase"),
	pat(`IT\.java$`, "junit", "java", ConfidenceHigh, "Java integration test (*IT.java)"),

	// ── Scala (file patterns before the JVM src/test/ directory rule) ──────
	pat(`Spec\.scala$`, "scalatest", "scala", ConfidenceHigh, "ScalaTest specification"),
	pat(`Suite\.scala$`, "scalatest", "scala", ConfidenceHigh, "ScalaTest suite"),
	pat(`Test\.scala$`, "scalatest", "scala", ConfidenceHigh, "Scala test file"),

	// ── JVM Maven/Gradle test directory (after language-specific file names) ─
	pat(`(^|/)src/test/`, "junit", "java", ConfidenceHigh, "Maven/Gradle src/test directory"),

	// ── Go ─────────────────────────────────────────────────────────────────
	pat(`_test\.go$`, "go test", "go", ConfidenceHigh, "Go test file (*_test.go)"),
	pat(`(^|/)testdata/`, "go test", "go", ConfidenceHigh, "Go testdata directory"),

	// ── Ruby ───────────────────────────────────────────────────────────────
	pat(`_spec\.rb$`, "rspec", "ruby", ConfidenceHigh, "RSpec specification (*_spec.rb)"),
	pat(`_test\.rb$`, "minitest", "ruby", ConfidenceHigh, "Minitest/Test::Unit file (*_test.rb)"),
	pat(`(^|/)spec/.*\.rb$`, "rspec", "ruby", ConfidenceHigh, "RSpec directory"),
	pat(`(^|/)test/.*\.rb$`, "minitest", "ruby", ConfidenceMedium, "Ruby test directory"),

	// ── Swift / Objective-C (before Rust so Tests/ wins for .swift) ────────
	pat(`Tests?\.swift$`, "xctest", "swift", ConfidenceHigh, "XCTest file"),
	pat(`(^|/)Tests/.*\.swift$`, "xctest", "swift", ConfidenceHigh, "Swift Tests directory"),
	pat(`Tests?\.m$`, "xctest", "objective-c", ConfidenceHigh, "Objective-C XCTest/OCUnit"),

	// ── C# / .NET (before generic Tests/) ──────────────────────────────────
	pat(`Tests?\.cs$`, "xunit", "c#", ConfidenceHigh, ".NET test file (xUnit/NUnit/MSTest)"),
	pat(`(^|/)Tests?/.*\.cs$`, "xunit", "c#", ConfidenceHigh, ".NET test directory"),

	// ── F# ─────────────────────────────────────────────────────────────────
	pat(`Tests?\.fs$`, "xunit", "f#", ConfidenceHigh, "F# test file"),

	// ── Visual Basic .NET ──────────────────────────────────────────────────
	pat(`Tests?\.vb$`, "mstest", "vb", ConfidenceHigh, "VB.NET test file"),

	// ── PHP ────────────────────────────────────────────────────────────────
	pat(`Test\.php$`, "phpunit", "php", ConfidenceHigh, "PHPUnit test file"),
	pat(`(^|/)tests?/.*\.php$`, "phpunit", "php", ConfidenceMedium, "PHP test directory"),

	// ── Rust ───────────────────────────────────────────────────────────────
	pat(`(^|/)tests/.*\.rs$`, "cargo test", "rust", ConfidenceHigh, "Rust integration tests directory"),
	pat(`_test\.rs$`, "cargo test", "rust", ConfidenceMedium, "Rust test file (*_test.rs)"),

	// ── Dart / Flutter ─────────────────────────────────────────────────────
	pat(`_test\.dart$`, "dart test", "dart", ConfidenceHigh, "Dart test file (*_test.dart)"),
	pat(`(^|/)test/.*\.dart$`, "dart test", "dart", ConfidenceHigh, "Dart test directory"),

	// ── Elixir ─────────────────────────────────────────────────────────────
	pat(`_test\.exs$`, "exunit", "elixir", ConfidenceHigh, "ExUnit test file (*_test.exs)"),
	pat(`(^|/)test/.*\.exs$`, "exunit", "elixir", ConfidenceHigh, "Elixir test directory"),

	// ── Erlang ─────────────────────────────────────────────────────────────
	pat(`_SUITE\.erl$`, "common test", "erlang", ConfidenceHigh, "Erlang Common Test suite"),
	pat(`_tests\.erl$`, "eunit", "erlang", ConfidenceHigh, "Erlang EUnit test"),

	// ── Haskell ────────────────────────────────────────────────────────────
	pat(`Spec\.hs$`, "hspec", "haskell", ConfidenceHigh, "Hspec specification"),
	pat(`Test\.hs$`, "hunit", "haskell", ConfidenceHigh, "Haskell test file"),
	pat(`(^|/)test/.*\.hs$`, "hspec", "haskell", ConfidenceMedium, "Haskell test directory"),

	// ── Clojure ────────────────────────────────────────────────────────────
	pat(`_test\.cljs?$`, "clojure.test", "clojure", ConfidenceHigh, "Clojure test file (*_test.clj[s])"),
	pat(`(^|/)test/.*\.cljc?$`, "clojure.test", "clojure", ConfidenceHigh, "Clojure test directory"),

	// ── C / C++ ────────────────────────────────────────────────────────────
	pat(`_test\.(c|cc|cpp|cxx)$`, "googletest", "c++", ConfidenceHigh, "C/C++ test file (*_test.*)"),
	pat(`_tests\.(c|cc|cpp|cxx)$`, "googletest", "c++", ConfidenceHigh, "C/C++ tests file (*_tests.*)"),
	pat(`(^|/)tests?/.*\.(c|cc|cpp|cxx|h|hpp)$`, "googletest", "c++", ConfidenceMedium, "C/C++ test directory"),

	// ── Perl ───────────────────────────────────────────────────────────────
	pat(`(^|/)t/.*\.t$`, "test::more", "perl", ConfidenceHigh, "Perl prove t/ directory"),
	pat(`\.t$`, "test::more", "perl", ConfidenceMedium, "Perl test file (*.t)"),

	// ── Lua ────────────────────────────────────────────────────────────────
	pat(`_spec\.lua$`, "busted", "lua", ConfidenceHigh, "Busted spec (*_spec.lua)"),
	pat(`(^|/)spec/.*\.lua$`, "busted", "lua", ConfidenceHigh, "Lua spec directory"),

	// ── R ──────────────────────────────────────────────────────────────────
	pat(`(^|/)tests/testthat/`, "testthat", "r", ConfidenceHigh, "testthat directory"),
	pat(`(^|/)test[-_][^/]+\.[rR]$`, "testthat", "r", ConfidenceHigh, "R test file (test-*.R)"),

	// ── Julia ──────────────────────────────────────────────────────────────
	pat(`(^|/)test/runtests\.jl$`, "test.jl", "julia", ConfidenceHigh, "Julia test entrypoint"),
	pat(`(^|/)test/.*\.jl$`, "test.jl", "julia", ConfidenceMedium, "Julia test directory"),

	// ── PowerShell ─────────────────────────────────────────────────────────
	pat(`\.Tests\.ps1$`, "pester", "powershell", ConfidenceHigh, "Pester test (*.Tests.ps1)"),

	// ── Shell / Bash ───────────────────────────────────────────────────────
	pat(`\.bats$`, "bats", "shell", ConfidenceHigh, "Bats test (*.bats)"),
	pat(`_test\.sh$`, "shunit2", "shell", ConfidenceMedium, "Shell test file (*_test.sh)"),

	// ── Objective-C / other X-family already covered above ─────────────────

	// ── VHDL / SystemVerilog (hardware) ────────────────────────────────────
	pat(`_tb\.(vhd|vhdl|sv)$`, "vunit", "vhdl", ConfidenceHigh, "HDL testbench (*_tb.*)"),

	// ── COBOL ──────────────────────────────────────────────────────────────
	pat(`Test\.cbl$`, "cobolunit", "cobol", ConfidenceMedium, "COBOL unit test"),

	// ── Generic directory fallbacks (lowest priority, framework unknown) ───
	pat(`(^|/)__tests__/`, "", "", ConfidenceHigh, "Generic __tests__ directory"),
	pat(`(^|/)tests?/`, "", "", ConfidenceMedium, "Generic test directory"),
	pat(`(^|/)spec/`, "", "", ConfidenceMedium, "Generic spec directory"),
	pat(`(^|/)features/`, "cucumber", "", ConfidenceLow, "Cucumber features directory"),
	pat(`(^|/)integration/`, "", "", ConfidenceLow, "Integration test directory"),
}

// confidenceScore maps a confidence label to a numeric rank for comparison.
func confidenceScore(c string) int {
	switch c {
	case ConfidenceConfirmed:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// DetectPath classifies a single file path by naming convention alone. It keeps
// the highest-confidence match; on a confidence tie it prefers a match that
// names a framework over one that leaves it ambiguous. A path matching nothing
// is production code (IsTestSuite false).
func DetectPath(filePath string) Detection {
	if filePath == "" {
		return Detection{}
	}
	norm := strings.ReplaceAll(filePath, "\\", "/")

	var best *testPattern
	for i := range testPatterns {
		p := &testPatterns[i]
		if !p.re.MatchString(norm) {
			continue
		}
		switch {
		case best == nil:
			best = p
		case confidenceScore(p.confidence) > confidenceScore(best.confidence):
			best = p
		case confidenceScore(p.confidence) == confidenceScore(best.confidence) && p.framework != "" && best.framework == "":
			best = p
		}
	}

	if best == nil {
		return Detection{IsTestSuite: false}
	}
	return Detection{
		IsTestSuite:    true,
		Framework:      best.framework,
		Language:       best.language,
		Confidence:     best.confidence,
		MatchedPattern: best.desc,
	}
}

// SupportedFrameworks returns the sorted set of frameworks the path table can
// name. Used by docs generation and tests.
func SupportedFrameworks() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range testPatterns {
		if p.framework != "" && !seen[p.framework] {
			seen[p.framework] = true
			out = append(out, p.framework)
		}
	}
	return sortStrings(out)
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
	return s
}
