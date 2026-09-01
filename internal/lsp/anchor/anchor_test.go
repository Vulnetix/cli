package anchor

import "testing"

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
