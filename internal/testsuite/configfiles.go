package testsuite

import (
	"path/filepath"
	"regexp"
	"strings"
)

// configFilesBudget bounds how many bytes of a candidate config file are read
// when a section marker must be checked. Config files are small; a data dump
// masquerading as one is skipped.
const configReadBudget = 256 * 1024

// configRule identifies a test-runner configuration file. A file is a config
// match when its basename matches `name` (exact) or `re` (glob-style), and —
// when `marker` is set — the file content contains that marker substring
// (needed for shared files like pyproject.toml or package.json that only
// indicate a runner via a section).
type configRule struct {
	name      string         // exact basename match (lowercased), optional
	re        *regexp.Regexp // basename regex, optional
	marker    string         // required content substring (lowercased), optional
	framework string
	language  string
	desc      string
}

func cname(name, framework, language, desc string) configRule {
	return configRule{name: strings.ToLower(name), framework: framework, language: language, desc: desc}
}

func cnameMarker(name, marker, framework, language, desc string) configRule {
	return configRule{name: strings.ToLower(name), marker: strings.ToLower(marker), framework: framework, language: language, desc: desc}
}

func cre(expr, framework, language, desc string) configRule {
	return configRule{re: regexp.MustCompile("(?i)^" + expr + "$"), framework: framework, language: language, desc: desc}
}

// configRules is the catalog of test-runner configuration files across every
// supported language. Marker-gated entries share a file with non-test config
// (pyproject.toml, package.json, setup.cfg, tox.ini) and only count as a test
// runner when the runner's section is present.
var configRules = []configRule{
	// ── JavaScript / TypeScript ────────────────────────────────────────────
	cre(`jest\.config\.(js|cjs|mjs|ts|json)`, "jest", "javascript", "Jest config"),
	cname("jest.config", "jest", "javascript", "Jest config"),
	cre(`\.mocharc\.(js|cjs|json|jsonc|yml|yaml)`, "mocha", "javascript", "Mocha config"),
	cre(`vitest\.config\.(js|cjs|mjs|ts|mts)`, "vitest", "javascript", "Vitest config"),
	cre(`vitest\.workspace\.(js|ts|json)`, "vitest", "javascript", "Vitest workspace"),
	cname("jasmine.json", "jasmine", "javascript", "Jasmine config"),
	cname("karma.conf.js", "karma", "javascript", "Karma config"),
	cre(`playwright\.config\.(js|ts|mjs)`, "playwright", "javascript", "Playwright config"),
	cre(`cypress\.config\.(js|ts|mjs)`, "cypress", "javascript", "Cypress config"),
	cname("cypress.json", "cypress", "javascript", "Cypress config (legacy)"),
	cre(`ava\.config\.(js|cjs|mjs)`, "ava", "javascript", "AVA config"),
	cname(".nycrc", "nyc", "javascript", "nyc/istanbul coverage config"),
	cnameMarker("package.json", "\"jest\"", "jest", "javascript", "Jest config in package.json"),
	cnameMarker("package.json", "\"ava\"", "ava", "javascript", "AVA config in package.json"),

	// ── Python ─────────────────────────────────────────────────────────────
	cname("pytest.ini", "pytest", "python", "pytest config"),
	cname("conftest.py", "pytest", "python", "pytest conftest"),
	cname("tox.ini", "tox", "python", "tox config"),
	cnameMarker("pyproject.toml", "[tool.pytest", "pytest", "python", "pytest config in pyproject.toml"),
	cnameMarker("setup.cfg", "[tool:pytest]", "pytest", "python", "pytest config in setup.cfg"),
	cnameMarker("pyproject.toml", "[tool.tox", "tox", "python", "tox config in pyproject.toml"),
	cname("nose.cfg", "nose", "python", "nose config"),
	cname(".noserc", "nose", "python", "nose config"),

	// ── PHP ────────────────────────────────────────────────────────────────
	cre(`phpunit\.xml(\.dist)?`, "phpunit", "php", "PHPUnit config"),
	cre(`\.phpunit\.result\.cache`, "phpunit", "php", "PHPUnit cache"),
	cname("codeception.yml", "codeception", "php", "Codeception config"),
	cname("pest.php", "pest", "php", "Pest config"),

	// ── Ruby ───────────────────────────────────────────────────────────────
	cname(".rspec", "rspec", "ruby", "RSpec config"),
	cname("spec_helper.rb", "rspec", "ruby", "RSpec helper"),
	cname("rails_helper.rb", "rspec", "ruby", "RSpec Rails helper"),

	// ── Java / Kotlin / Scala (JVM) ────────────────────────────────────────
	cnameMarker("pom.xml", "junit", "junit", "java", "JUnit dependency in pom.xml"),
	cnameMarker("pom.xml", "testng", "testng", "java", "TestNG dependency in pom.xml"),
	cnameMarker("build.gradle", "junit", "junit", "java", "JUnit dependency in build.gradle"),
	cnameMarker("build.gradle.kts", "junit", "junit", "kotlin", "JUnit dependency in build.gradle.kts"),
	cnameMarker("build.gradle", "spock", "spock", "groovy", "Spock dependency in build.gradle"),
	cnameMarker("build.sbt", "scalatest", "scalatest", "scala", "ScalaTest dependency in build.sbt"),

	// ── Go ─────────────────────────────────────────────────────────────────
	// go test needs no config file; presence of go.mod is a weak signal only
	// (handled by declared-dependency detection for testify et al).

	// ── Rust ───────────────────────────────────────────────────────────────
	cnameMarker("cargo.toml", "[dev-dependencies]", "cargo test", "rust", "Cargo dev-dependencies"),

	// ── .NET ───────────────────────────────────────────────────────────────
	cnameMarker("*.csproj", "microsoft.net.test.sdk", "xunit", "c#", ".NET test SDK in project"),
	cname("xunit.runner.json", "xunit", "c#", "xUnit runner config"),
	cname("nunit.config", "nunit", "c#", "NUnit config"),

	// ── Dart / Flutter ─────────────────────────────────────────────────────
	cname("dart_test.yaml", "dart test", "dart", "Dart test config"),

	// ── Elixir ─────────────────────────────────────────────────────────────
	cname("test_helper.exs", "exunit", "elixir", "ExUnit helper"),

	// ── Haskell ────────────────────────────────────────────────────────────
	cname("hspec.hs", "hspec", "haskell", "Hspec config"),

	// ── PowerShell ─────────────────────────────────────────────────────────
	cre(`.*\.tests\.ps1`, "pester", "powershell", "Pester test script"),

	// ── R ──────────────────────────────────────────────────────────────────
	cname("testthat.r", "testthat", "r", "testthat runner"),

	// ── Julia ──────────────────────────────────────────────────────────────
	cname("runtests.jl", "test.jl", "julia", "Julia test entrypoint"),

	// ── C / C++ ────────────────────────────────────────────────────────────
	cnameMarker("cmakelists.txt", "gtest", "googletest", "c++", "GoogleTest in CMake"),
	cnameMarker("cmakelists.txt", "catch2", "catch2", "c++", "Catch2 in CMake"),
	cnameMarker("conanfile.txt", "gtest", "googletest", "c++", "GoogleTest in Conan"),

	// ── Hardware (VHDL/SystemVerilog) ──────────────────────────────────────
	cname("run.py", "vunit", "vhdl", "VUnit run script"),

	// ── Cross-language BDD ─────────────────────────────────────────────────
	cname("cucumber.yml", "cucumber", "", "Cucumber config"),
	cname("behave.ini", "behave", "python", "Behave config"),
}

// matchConfig reports whether a basename + (optionally) content matches this
// rule. `content` may be empty when the rule needs no marker.
func (r configRule) matchConfig(base, lowerContent string) bool {
	nameOK := false
	switch {
	case r.name != "":
		if strings.HasPrefix(r.name, "*.") {
			nameOK = strings.HasSuffix(base, r.name[1:])
		} else {
			nameOK = base == r.name
		}
	case r.re != nil:
		nameOK = r.re.MatchString(base)
	}
	if !nameOK {
		return false
	}
	if r.marker == "" {
		return true
	}
	return strings.Contains(lowerContent, r.marker)
}

// needsContent reports whether any rule that could match this basename requires
// reading the file (has a marker). Lets the walker skip I/O for name-only rules.
func configNeedsContent(base string) bool {
	for _, r := range configRules {
		if r.marker == "" {
			continue
		}
		if r.name != "" {
			if strings.HasPrefix(r.name, "*.") {
				if strings.HasSuffix(base, r.name[1:]) {
					return true
				}
			} else if base == r.name {
				return true
			}
		} else if r.re != nil && r.re.MatchString(base) {
			return true
		}
	}
	return false
}

// contentTypeForExt returns a coarse content-type for a config file extension,
// mirroring the manifest content-type convention used on the SCA path.
func contentTypeForExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".toml":
		return "application/toml"
	case ".xml", ".csproj", ".fsproj", ".vbproj":
		return "application/xml"
	case ".ini", ".cfg", ".conf":
		return "text/plain"
	default:
		return "text/plain"
	}
}
