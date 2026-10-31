package anchor

import (
	"strings"
	"testing"
)

// The cases below mirror the "anchors" block of the extension fixture at
// vulnetix-vscode/test/fixtures/vulnetix-fixture-app/.vulnetix/expected.json,
// which is hand-maintained precisely so it does not agree with whatever this
// implementation happens to do.
func TestFindMatchesFixtureAnchors(t *testing.T) {
	packageJSON := `{
  "name": "vulnetix-fixture-app",
  "version": "1.0.0",
  "private": true,
  "description": "Intentionally vulnerable fixture. Do not deploy.",
  "license": "AGPL-3.0-only",
  "scripts": {
    "start": "node src/vuln.js"
  },
  "dependencies": {
    "lodash": "4.17.20",
    "minimist": "0.0.8",
    "express": "4.16.0"
  }
}`

	packageLock := `{
  "name": "vulnetix-fixture-app",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "vulnetix-fixture-app"
    },
    "node_modules/express": {
      "version": "4.16.0"
    },
    "node_modules/lodash": {
      "version": "4.17.20"
    },
    "node_modules/minimist": {
      "version": "0.0.8"
    },
    "node_modules/qs": {
      "version": "6.5.1"
    }
  }
}`

	goMod := `module github.com/vulnetix/vulnetix-fixture-app

go 1.21

require golang.org/x/text v0.3.0

require golang.org/x/net v0.0.0-20190311183353-d8887717615a // indirect
`

	requirements := `# Pinned deliberately to versions with known advisories.
requests==2.19.1
PyYAML==5.1
Jinja2==2.10
`

	cargoToml := `[package]
name = "vulnetix-fixture-app"
version = "1.0.0"
edition = "2021"
publish = false

[dependencies]
time = "0.1.44"
`

	gemfile := `source "https://rubygems.org"

gem "rack", "2.0.6"
gem "nokogiri", "1.10.4"
`

	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.vulnetix.fixture</groupId>
  <artifactId>vulnetix-fixture-app</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <!-- Log4Shell. Present so the fixture covers a CISA KEV entry, which is
         what the exploit-maturity and KEV badges render from. -->
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>`

	cases := []struct {
		name         string
		text         string
		manifestType string
		pkg          string
		wantLine     int
		wantConf     Confidence
	}{
		{"maven", pomXML, "pom.xml", "org.apache.logging.log4j:log4j-core", 14, ConfidenceToken},
		{"npm lodash", packageJSON, "package.json", "lodash", 11, ConfidenceExact},
		{"npm minimist", packageJSON, "package.json", "minimist", 12, ConfidenceExact},
		{"npm express", packageJSON, "package.json", "express", 13, ConfidenceExact},
		{"npm lock qs", packageLock, "package-lock.json", "qs", 17, ConfidenceExact},
		{"golang x/text", goMod, "go.mod", "golang.org/x/text", 5, ConfidenceExact},
		{"pypi requests", requirements, "requirements.txt", "requests", 2, ConfidenceExact},
		{"pypi pyyaml normalised", requirements, "requirements.txt", "pyyaml", 3, ConfidenceExact},
		{"cargo time", cargoToml, "Cargo.toml", "time", 8, ConfidenceToken},
		{"gem rack", gemfile, "Gemfile", "rack", 3, ConfidenceExact},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Find(tc.text, tc.manifestType, tc.pkg)
			if !ok {
				t.Fatalf("Find(%s, %s) found nothing", tc.manifestType, tc.pkg)
			}
			if got.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tc.wantLine)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("confidence = %q, want %q", got.Confidence, tc.wantConf)
			}
		})
	}
}

// The manifest's own metadata keys share names with real packages. Anchoring on
// them would put a dependency finding on an unrelated line.
func TestFindIgnoresTopLevelMetadataKeys(t *testing.T) {
	manifest := `{
  "name": "my-app",
  "version": "1.0.0",
  "license": "MIT",
  "dependencies": {
    "left-pad": "1.3.0"
  }
}`
	for _, pkg := range []string{"name", "version", "license"} {
		if got, ok := Find(manifest, "package.json", pkg); ok {
			t.Errorf("Find(%q) anchored line %d; top-level metadata is not a dependency", pkg, got.Line)
		}
	}
	got, ok := Find(manifest, "package.json", "left-pad")
	if !ok || got.Line != 6 {
		t.Errorf("left-pad = %+v, %v; want line 6", got, ok)
	}
}

// Cargo's [package] table has a bare `name` key. A dependency lookup must not
// land on the crate being built.
func TestFindCargoIgnoresPackageTable(t *testing.T) {
	manifest := `[package]
name = "time"
version = "1.0.0"

[dependencies]
serde = "1.0"
`
	got, ok := Find(manifest, "Cargo.toml", "time")
	if ok {
		t.Errorf("anchored line %d; `time` is the crate name, not a dependency", got.Line)
	}
	if got, ok := Find(manifest, "Cargo.toml", "serde"); !ok || got.Line != 6 {
		t.Errorf("serde = %+v, %v; want line 6", got, ok)
	}
}

// A go.mod path is a prefix of longer paths. Matching must be token-wise.
func TestFindGoModDoesNotMatchLongerPaths(t *testing.T) {
	manifest := `module example.com/app

require (
	golang.org/x/text/encoding v0.1.0
	golang.org/x/text v0.3.0
)
`
	got, ok := Find(manifest, "go.mod", "golang.org/x/text")
	if !ok {
		t.Fatal("golang.org/x/text not found")
	}
	if got.Line != 5 {
		t.Errorf("line = %d, want 5 (the exact module, not its subpackage)", got.Line)
	}
}

// The buffer is frequently mid-edit and not valid JSON. Refusing to anchor then
// is the failure mode this package exists to avoid.
func TestFindWorksOnUnbalancedBuffer(t *testing.T) {
	manifest := `{
  "dependencies": {
    "lodash": "4.17.20",
    "express": "4.16.
`
	got, ok := Find(manifest, "package.json", "lodash")
	if !ok || got.Line != 3 {
		t.Errorf("lodash = %+v, %v; want line 3 on a truncated buffer", got, ok)
	}
}

func TestFindEmptyInputs(t *testing.T) {
	if _, ok := Find("", "package.json", "lodash"); ok {
		t.Error("empty text should not anchor")
	}
	if _, ok := Find(`{"dependencies":{"a":"1"}}`, "package.json", ""); ok {
		t.Error("empty name should not anchor")
	}
	if _, ok := Find("nothing here", "package.json", "absent"); ok {
		t.Error("absent package should not anchor")
	}
}

func TestNormalizePyPI(t *testing.T) {
	cases := map[string]string{
		"PyYAML":            "pyyaml",
		"zope.interface":    "zope-interface",
		"typing_extensions": "typing-extensions",
		"Flask--SQLAlchemy": "flask-sqlalchemy",
	}
	for in, want := range cases {
		if got := normalizePyPI(in); got != want {
			t.Errorf("normalizePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}

// The lockfile resolvers below were untested. Each case pins the line and
// confidence the resolver's doc comment promises.
func TestFindLockfileResolvers(t *testing.T) {
	composerJSON := `{
  "require": {
    "guzzlehttp/guzzle": "7.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^9"
  }
}`

	composerLock := `{
    "packages": [
        {
            "name": "guzzlehttp/guzzle",
            "version": "7.0.0"
        }
    ]
}`

	yarnLock := `# yarn lockfile v1

# lodash@ appears in this comment, must be skipped
underscore@^1.13.0:
  lodash@ appears indented under another entry, must be skipped
  version "1.13.6"

lodash@^4.17.0, lodash@^4.17.20:
  version "4.17.21"
`

	pnpmLockV5 := `lockfileVersion: 5.4

packages:

  /lodash@4.17.20:
    resolution: {integrity: sha512-1}
`

	pnpmLockV6 := `lockfileVersion: '6.0'

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-1}
`

	goSum := `golang.org/x/text v0.3.0 h1:g6yoYrW7aWVXxIt6QgOj4Wr8DMhCJjOxe4c6p2b3z04=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
`

	cargoLock := `# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "time"
version = "0.1.44"
source = "registry+https://github.com/rust-lang/crates.io-index"
`

	pipfileLock := `{
    "_meta": {
        "hash": {"sha256": "abc"}
    },
    "default": {
        "requests": {
            "version": "==2.19.1"
        }
    }
}`

	gemfileLock := `GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.6)
    nokogiri (1.10.4)
`

	cases := []struct {
		name         string
		text         string
		manifestType string
		pkg          string
		wantLine     int
		wantConf     Confidence
	}{
		{"composer.json require block", composerJSON, "composer.json", "guzzlehttp/guzzle", 3, ConfidenceExact},
		{"composer.lock name field", composerLock, "composer.lock", "guzzlehttp/guzzle", 4, ConfidenceExact},
		{"yarn.lock header", yarnLock, "yarn.lock", "lodash", 8, ConfidenceExact},
		{"pnpm-lock v5 slash key", pnpmLockV5, "pnpm-lock.yaml", "lodash", 5, ConfidenceExact},
		{"pnpm-lock v6 bare key", pnpmLockV6, "pnpm-lock.yaml", "lodash", 5, ConfidenceExact},
		{"go.sum checksum", goSum, "go.sum", "golang.org/x/text", 1, ConfidenceExact},
		{"cargo lock toml", cargoLock, "Cargo.lock", "time", 5, ConfidenceExact},
		{"pipfile lock json", pipfileLock, "Pipfile.lock", "requests", 6, ConfidenceExact},
		{"gemfile.lock spec", gemfileLock, "Gemfile.lock", "rack", 4, ConfidenceExact},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Find(tc.text, tc.manifestType, tc.pkg)
			if !ok {
				t.Fatalf("Find(%s, %s) found nothing", tc.manifestType, tc.pkg)
			}
			if got.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tc.wantLine)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("confidence = %q, want %q", got.Confidence, tc.wantConf)
			}
		})
	}
}

func TestFindPyprojectForms(t *testing.T) {
	poetryTable := `[tool.poetry.dependencies]
python = "^3.8"
requests = "^2.0"
`

	poetryHeader := `[tool.poetry.dependencies]
python = "^3.8"

[tool.poetry.dependencies.requests]
version = "^2.0"
`

	pep621 := `[project]
name = "example"
dependencies = [
    "requests>=2.0",
    "flask>=2.0"
]
`

	cases := []struct {
		name         string
		text         string
		manifestType string
		pkg          string
		wantLine     int
		wantConf     Confidence
	}{
		{"poetry table key", poetryTable, "pyproject.toml", "requests", 3, ConfidenceExact},
		{"poetry bracketed header", poetryHeader, "pyproject.toml", "requests", 4, ConfidenceToken},
		{"pep 621 array entry", pep621, "pyproject.toml", "requests", 4, ConfidenceExact},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Find(tc.text, tc.manifestType, tc.pkg)
			if !ok {
				t.Fatalf("Find(%s, %s) found nothing", tc.manifestType, tc.pkg)
			}
			if got.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tc.wantLine)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("confidence = %q, want %q", got.Confidence, tc.wantConf)
			}
		})
	}
}

func TestFindGradleForms(t *testing.T) {
	compact := `dependencies {
    implementation 'com.google.guava:guava:31.0'
}
`

	mapForm := `dependencies {
    implementation group: 'com.google.guava', name: 'guava', version: '31.0'
}
`

	noColon := `dependencies {
    implementation name: 'guava', version: '31.0'
}
`

	cases := []struct {
		name         string
		text         string
		manifestType string
		pkg          string
		wantLine     int
		wantConf     Confidence
	}{
		{"compact coordinate", compact, "build.gradle", "com.google.guava:guava", 2, ConfidenceExact},
		{"map form", mapForm, "build.gradle", "com.google.guava:guava", 2, ConfidenceToken},
		{"bare artifact matches its quoted name as a compact coordinate", noColon, "build.gradle", "guava", 2, ConfidenceExact},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Find(tc.text, tc.manifestType, tc.pkg)
			if !ok {
				t.Fatalf("Find(%s, %s) found nothing", tc.manifestType, tc.pkg)
			}
			if got.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tc.wantLine)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("confidence = %q, want %q", got.Confidence, tc.wantConf)
			}
		})
	}
}

func TestFindLiteralFallback(t *testing.T) {
	text := `FROM golang:1.21

RUN go install time@latest
`
	got, ok := Find(text, "Dockerfile", "time")
	if !ok || got.Line != 3 || got.Confidence != ConfidenceToken {
		t.Errorf("time = %+v, %v; want line 3 token", got, ok)
	}

	// "runtime" contains "time" but is not a delimited token for it.
	if got, ok := Find("runtime", "Dockerfile", "time"); ok {
		t.Errorf("anchored %+v; a substring must not match", got)
	}
}

func TestFindNPMLockV1(t *testing.T) {
	lock := `{
  "name": "my-app",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.20"
    }
  }
}`
	got, ok := Find(lock, "package-lock.json", "lodash")
	if !ok {
		t.Fatal("lodash not found")
	}
	if got.Line != 5 {
		t.Errorf("line = %d, want 5", got.Line)
	}
	if got.Confidence != ConfidenceExact {
		t.Errorf("confidence = %q, want %q", got.Confidence, ConfidenceExact)
	}
}

func TestFindPomGroupMismatch(t *testing.T) {
	pom := `<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.0</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>guava</artifactId>
      <version>31.0</version>
    </dependency>
  </dependencies>
</project>`
	got, ok := Find(pom, "pom.xml", "org.example:guava")
	if !ok {
		t.Fatal("org.example:guava not found")
	}
	if got.Line != 8 {
		t.Errorf("line = %d, want 8 (the matching dependency element, not the first artifactId)", got.Line)
	}
	if got.Confidence != ConfidenceToken {
		t.Errorf("confidence = %q, want %q", got.Confidence, ConfidenceToken)
	}
}

func TestFindBunLock(t *testing.T) {
	text := "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"alias\": [\"real-pkg@2.0.0\", \"\", {}, \"sha512-A\"],\n\n    \"app/@s/x\": [\"@s/x@1.0.0\", \"\", {}, \"sha512-B\"],\n  }\n}\n"
	lines := strings.Split(text, "\n")
	if r, ok := findBunLock(lines, "@s/x"); !ok || r.Line != 6 {
		t.Errorf("@s/x: got %+v ok=%v, want line 6", r, ok)
	}
	if r, ok := findBunLock(lines, "real-pkg"); !ok || r.Line != 4 {
		t.Errorf("an alias is anchored by its real name: got %+v ok=%v", r, ok)
	}
	if _, ok := findBunLock(lines, "alias"); ok {
		t.Error("the install key is not the package")
	}
}
