package testsuite

import "strings"

// manifestReadBudget bounds bytes read from a manifest when scanning for
// declared test-framework dependencies.
const manifestReadBudget = 512 * 1024

// depToken maps a package-name token that appears in a manifest's dependency
// list to the test framework it implies. Matching is a case-insensitive
// substring check against the manifest body — deliberately loose, since it only
// contributes corroborating evidence (a declared dependency), never a finding on
// its own. The token is chosen to be specific enough to avoid obvious
// collisions (e.g. "@playwright/test", "pytest", "rspec").
type depToken struct {
	token     string
	framework string
	language  string
}

// manifestDepTokens are checked against every collected manifest body. Keep
// tokens distinctive; a bare "test" would false-positive constantly.
var manifestDepTokens = []depToken{
	// JavaScript / TypeScript (package.json dev-dependencies)
	{"\"jest\"", "jest", "javascript"},
	{"ts-jest", "jest", "javascript"},
	{"\"mocha\"", "mocha", "javascript"},
	{"\"vitest\"", "vitest", "javascript"},
	{"\"jasmine\"", "jasmine", "javascript"},
	{"\"cypress\"", "cypress", "javascript"},
	{"@playwright/test", "playwright", "javascript"},
	{"\"ava\"", "ava", "javascript"},
	{"@testing-library/", "testing-library", "javascript"},
	{"\"tape\"", "tape", "javascript"},
	{"\"qunit\"", "qunit", "javascript"},

	// Python
	{"pytest", "pytest", "python"},
	{"nose2", "nose", "python"},
	{"\"nose\"", "nose", "python"},
	{"unittest2", "unittest", "python"},
	{"hypothesis", "hypothesis", "python"},

	// Ruby
	{"rspec", "rspec", "ruby"},
	{"minitest", "minitest", "ruby"},
	{"test-unit", "test::unit", "ruby"},

	// Java / Kotlin / Scala / Groovy (pom.xml, build.gradle, build.sbt)
	{"junit", "junit", "java"},
	{"testng", "testng", "java"},
	{"org.spockframework", "spock", "groovy"},
	{"io.kotest", "kotest", "kotlin"},
	{"org.scalatest", "scalatest", "scala"},
	{"mockito", "mockito", "java"},
	{"assertj", "junit", "java"},

	// Go
	{"stretchr/testify", "testify", "go"},
	{"onsi/ginkgo", "ginkgo", "go"},
	{"gotest.tools", "go test", "go"},

	// Rust
	{"proptest", "proptest", "rust"},
	{"quickcheck", "quickcheck", "rust"},
	{"criterion", "criterion", "rust"},

	// PHP
	{"phpunit/phpunit", "phpunit", "php"},
	{"pestphp/pest", "pest", "php"},
	{"codeception/codeception", "codeception", "php"},

	// .NET
	{"xunit", "xunit", "c#"},
	{"nunit", "nunit", "c#"},
	{"mstest", "mstest", "c#"},
	{"microsoft.net.test.sdk", "xunit", "c#"},

	// Dart / Flutter
	{"flutter_test", "flutter test", "dart"},

	// Elixir
	{"ex_unit", "exunit", "elixir"},

	// Haskell
	{"hspec", "hspec", "haskell"},
	{"HUnit", "hunit", "haskell"},
	{"tasty", "tasty", "haskell"},

	// C / C++
	{"gtest", "googletest", "c++"},
	{"googletest", "googletest", "c++"},
	{"catch2", "catch2", "c++"},
	{"doctest", "doctest", "c++"},

	// Perl
	{"Test::More", "test::more", "perl"},

	// R
	{"testthat", "testthat", "r"},

	// PowerShell
	{"Pester", "pester", "powershell"},

	// Lua
	{"busted", "busted", "lua"},

	// Clojure
	{"midje", "midje", "clojure"},
}

// declaredFrameworks scans one manifest body for declared test frameworks.
// Returns framework→true and framework→evidence-string.
func declaredFrameworks(manifestPath, body string) map[string]string {
	if len(body) > manifestReadBudget {
		body = body[:manifestReadBudget]
	}
	lower := strings.ToLower(body)
	out := map[string]string{}
	for _, dt := range manifestDepTokens {
		if strings.Contains(lower, strings.ToLower(dt.token)) {
			// First occurrence wins the evidence string for a framework.
			if _, seen := out[dt.framework]; !seen {
				out[dt.framework] = "dep:" + dt.token + " (" + manifestPath + ")"
			}
		}
	}
	return out
}
