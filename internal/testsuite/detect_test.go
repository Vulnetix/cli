package testsuite

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/internal/sast"
)

func TestDetectPath(t *testing.T) {
	cases := []struct {
		path     string
		wantTest bool
		wantFwk  string
		wantLang string
	}{
		// JavaScript / TypeScript
		{"src/utils/parser.test.ts", true, "jest", "javascript"},
		{"src/utils/parser.spec.js", true, "jasmine", "javascript"},
		{"e2e/login.e2e-spec.ts", true, "playwright", "javascript"},
		{"cypress/e2e/app.cy.js", true, "cypress", "javascript"},
		{"src/__tests__/foo.js", true, "jest", "javascript"},
		// Python
		{"tests/test_parser.py", true, "pytest", "python"},
		{"parser_test.py", true, "pytest", "python"},
		{"conftest.py", true, "pytest", "python"},
		// Go
		{"internal/scan/detector_test.go", true, "go test", "go"},
		{"testdata/fixture.json", true, "go test", "go"},
		// Java / Kotlin / Scala / Groovy
		{"src/test/java/com/foo/BarTest.java", true, "junit", "java"},
		{"app/src/test/kotlin/BarSpec.kt", true, "kotest", "kotlin"},
		{"src/test/scala/FooSpec.scala", true, "scalatest", "scala"},
		{"src/test/groovy/FooSpec.groovy", true, "spock", "groovy"},
		// Ruby
		{"spec/models/user_spec.rb", true, "rspec", "ruby"},
		{"test/user_test.rb", true, "minitest", "ruby"},
		// Swift / C# / PHP / Rust
		{"Tests/AppTests/FooTests.swift", true, "xctest", "swift"},
		{"tests/FooTests.cs", true, "xunit", "c#"},
		{"tests/FooTest.php", true, "phpunit", "php"},
		{"tests/integration.rs", true, "cargo test", "rust"},
		// Additional languages
		{"test/widget_test.dart", true, "dart test", "dart"},
		{"test/foo_test.exs", true, "exunit", "elixir"},
		{"test/FooSpec.hs", true, "hspec", "haskell"},
		{"src/foo_test.clj", true, "clojure.test", "clojure"},
		{"tests/foo_test.cpp", true, "googletest", "c++"},
		{"t/basic.t", true, "test::more", "perl"},
		{"spec/foo_spec.lua", true, "busted", "lua"},
		{"tests/testthat/test-foo.R", true, "testthat", "r"},
		{"test/runtests.jl", true, "test.jl", "julia"},
		{"Foo.Tests.ps1", true, "pester", "powershell"},
		{"tests/foo.bats", true, "bats", "shell"},
		// Production code — must NOT be flagged
		{"src/main.go", false, "", ""},
		{"lib/parser.ts", false, "", ""},
		{"cmd/root.go", false, "", ""},
		{"", false, "", ""},
	}
	for _, c := range cases {
		got := DetectPath(c.path)
		if got.IsTestSuite != c.wantTest {
			t.Errorf("DetectPath(%q).IsTestSuite = %v, want %v", c.path, got.IsTestSuite, c.wantTest)
			continue
		}
		if c.wantTest && got.Framework != c.wantFwk {
			t.Errorf("DetectPath(%q).Framework = %q, want %q", c.path, got.Framework, c.wantFwk)
		}
		if c.wantTest && got.Language != c.wantLang {
			t.Errorf("DetectPath(%q).Language = %q, want %q", c.path, got.Language, c.wantLang)
		}
	}
}

func TestScanAndAnnotate(t *testing.T) {
	dir := t.TempDir()
	// A jest.config.js + package.json declaring jest → active framework "jest".
	writeFile(t, dir, "jest.config.js", "module.exports = {};")
	writeFile(t, dir, "package.json", `{"devDependencies":{"jest":"^29.0.0"}}`)
	writeFile(t, dir, "src/util.test.js", "test('x', () => {});")

	act := Scan(dir)
	if !act.Present["jest"] {
		t.Fatalf("expected jest active, got %+v", act.Present)
	}
	if len(act.Configs) == 0 {
		t.Fatalf("expected at least one config file detected")
	}

	findings := []sast.Finding{
		{RuleID: "R1", ArtifactURI: "src/util.test.js"},
		{RuleID: "R2", ArtifactURI: "src/util.js"},
	}
	marked := Annotate(findings, act)
	if marked != 1 {
		t.Fatalf("expected 1 finding marked, got %d", marked)
	}
	if !findings[0].IsTestSuite || findings[0].TestFramework != "jest" {
		t.Errorf("finding[0] not attributed to jest: %+v", findings[0])
	}
	// Path + config + dep corroboration → confirmed.
	if findings[0].TestConfidence != ConfidenceConfirmed {
		t.Errorf("finding[0] confidence = %q, want confirmed", findings[0].TestConfidence)
	}
	if findings[1].IsTestSuite {
		t.Errorf("finding[1] (production) wrongly attributed: %+v", findings[1])
	}
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
