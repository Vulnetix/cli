package agent

import (
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// want is a compact spelling of one expected candidate: "ecosystem:name@version".
func fingerprint(c Candidate) string {
	s := c.Ecosystem + ":" + c.Name
	if c.Version != "" {
		s += "@" + c.Version
	}
	return s
}

func TestParseInstallCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		// ── the common shapes, one per manager ──────────────────────────────
		{"npm install", "npm install axios", []string{"npm:axios"}},
		{"npm i short", "npm i axios", []string{"npm:axios"}},
		{"yarn add", "yarn add axios", []string{"npm:axios"}},
		{"pnpm add", "pnpm add axios", []string{"npm:axios"}},
		{"bun add", "bun add axios", []string{"npm:axios"}},
		{"deno add", "deno add axios", []string{"npm:axios"}},
		{"pip install", "pip install requests", []string{"pypi:requests"}},
		{"pip3 install", "pip3 install requests", []string{"pypi:requests"}},
		{"uv add", "uv add requests", []string{"pypi:requests"}},
		{"poetry add", "poetry add requests", []string{"pypi:requests"}},
		{"pdm add", "pdm add requests", []string{"pypi:requests"}},
		{"pipenv install", "pipenv install requests", []string{"pypi:requests"}},
		{"conda install", "conda install requests", []string{"pypi:requests"}},
		{"cargo add", "cargo add serde", []string{"cargo:serde"}},
		{"gem install", "gem install rails", []string{"rubygems:rails"}},
		{"bundle add", "bundle add rails", []string{"rubygems:rails"}},
		{"composer require", "composer require monolog/monolog", []string{"composer:monolog/monolog"}},
		{"go get", "go get github.com/gin-gonic/gin", []string{"golang:github.com/gin-gonic/gin"}},
		{"dotnet add package", "dotnet add package Newtonsoft.Json", []string{"nuget:Newtonsoft.Json"}},
		{"mvn dependency:get", "mvn dependency:get -Dartifact=x", nil},

		// ── version pins, per ecosystem's own spelling ──────────────────────
		{"npm pin", "npm i axios@1.2.3", []string{"npm:axios@1.2.3"}},
		{"npm range", "npm i axios@^1.2.3", []string{"npm:axios@^1.2.3"}},
		{"npm scoped", "npm i @scope/pkg", []string{"npm:@scope/pkg"}},
		{"npm scoped pinned", "npm i @scope/pkg@1.0.0", []string{"npm:@scope/pkg@1.0.0"}},
		{"npm dist tag", "npm i axios@latest", []string{"npm:axios@latest"}},
		{"pip pin", "pip install requests==2.31.0", []string{"pypi:requests@2.31.0"}},
		{"pip gte", "pip install 'requests>=2.0'", []string{"pypi:requests@2.0"}},
		{"pip compound", "pip install 'requests>=2.0,<3'", []string{"pypi:requests@2.0"}},
		{"pip extras", "pip install 'requests[security]==2.31.0'", []string{"pypi:requests@2.31.0"}},
		{"pip extras bare", "pip install requests[security]", []string{"pypi:requests"}},
		{"cargo pin", "cargo add serde@1.0.100", []string{"cargo:serde@1.0.100"}},
		{"go pin", "go get github.com/gin-gonic/gin@v1.9.1", []string{"golang:github.com/gin-gonic/gin@v1.9.1"}},
		{"composer pin", "composer require monolog/monolog:^3.0", []string{"composer:monolog/monolog@^3.0"}},
		{"maven coords", "mvn dependency:get org.apache.logging.log4j:log4j-core:2.14.1",
			[]string{"maven:org.apache.logging.log4j:log4j-core@2.14.1"}},

		// ── several packages on one line ────────────────────────────────────
		{"npm many", "npm i axios lodash express", []string{"npm:axios", "npm:lodash", "npm:express"}},
		{"pip many", "pip install requests flask", []string{"pypi:requests", "pypi:flask"}},
		{"npm many mixed pins", "npm i axios@1.2.3 lodash", []string{"npm:axios@1.2.3", "npm:lodash"}},

		// ── flags must not be mistaken for package names ────────────────────
		{"npm save-dev", "npm install --save-dev axios", []string{"npm:axios"}},
		{"npm -D", "npm i -D axios", []string{"npm:axios"}},
		{"npm workspace value flag", "npm i -w web axios", []string{"npm:axios"}},
		{"npm workspace equals", "npm i --workspace=web axios", []string{"npm:axios"}},
		{"pnpm filter", "pnpm add -F @app/web axios", []string{"npm:axios"}},
		{"pip index url", "pip install -i https://example.test/simple requests", []string{"pypi:requests"}},
		{"poetry group", "poetry add --group dev pytest", []string{"pypi:pytest"}},
		{"cargo features", "cargo add serde --features derive", []string{"cargo:serde"}},
		{"gem version flag", "gem install rails -v 7.0.0", []string{"rubygems:rails"}},
		{"double dash", "npm i -- axios", []string{"npm:axios"}},

		// ── longest-verb matching ───────────────────────────────────────────
		{"uv pip install", "uv pip install requests", []string{"pypi:requests"}},

		// ── wrappers and prefixes ───────────────────────────────────────────
		{"env prefix", "NODE_ENV=production npm i axios", []string{"npm:axios"}},
		{"sudo", "sudo pip install requests", []string{"pypi:requests"}},
		{"absolute path binary", "/usr/local/bin/npm install axios", []string{"npm:axios"}},

		// ── chained commands ────────────────────────────────────────────────
		{"cd then install", "cd web && npm i axios", []string{"npm:axios"}},
		{"install then build", "npm i axios && npm run build", []string{"npm:axios"}},
		{"semicolon", "npm i axios; npm i lodash", []string{"npm:axios", "npm:lodash"}},
		{"or operator", "npm i axios || true", []string{"npm:axios"}},
		{"pipe", "echo hi | npm i axios", []string{"npm:axios"}},

		// ── deduplication ───────────────────────────────────────────────────
		{"same package twice", "npm i axios && npm i axios", []string{"npm:axios"}},

		// ── everything that must stay silent ────────────────────────────────
		{"bare npm install", "npm install", nil},
		{"bare pnpm install", "pnpm install", nil},
		{"npm ci", "npm ci", nil},
		{"requirements file", "pip install -r requirements.txt", nil},
		{"constraints file", "pip install -c constraints.txt", nil},
		{"editable local", "pip install -e .", nil},
		{"local path", "npm i ./local-pkg", nil},
		{"parent path", "npm i ../sibling", nil},
		{"absolute path pkg", "npm i /opt/pkg", nil},
		{"home path", "pip install ~/wheels/pkg", nil},
		{"tarball url", "npm i https://example.test/pkg.tgz", nil},
		{"git url", "npm i git+https://example.test/pkg.git", nil},
		{"git ssh", "go get git@example.test:org/repo", nil},
		{"local wheel", "pip install ./dist/pkg-1.0-py3-none-any.whl", nil},
		{"go glob", "go get ./...", nil},
		{"unrelated command", "ls -la", nil},
		{"npm run", "npm run build", nil},
		{"go build", "go build ./...", nil},
		{"dotnet add reference", "dotnet add reference ../other/other.csproj", nil},
		{"empty", "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseInstallCommand(tc.command)
			var fps []string
			for _, c := range got {
				fps = append(fps, fingerprint(c))
			}
			if strings.Join(fps, ",") != strings.Join(tc.want, ",") {
				t.Errorf("ParseInstallCommand(%q)\n got: %v\nwant: %v", tc.command, fps, tc.want)
			}
		})
	}
}

func TestParseInstallCommandDotnetProjectArgument(t *testing.T) {
	// `dotnet add [PROJECT] package NAME` puts an optional project path between
	// the verb and the keyword; the keyword has to anchor the scan or the
	// project file is read as the package.
	got := ParseInstallCommand("dotnet add ./src/App.csproj package Newtonsoft.Json --version 13.0.3")
	if len(got) != 1 || got[0].Name != "Newtonsoft.Json" || got[0].Ecosystem != "nuget" {
		t.Fatalf("got %+v, want the single nuget package Newtonsoft.Json", got)
	}
}

func TestParseInstallCommandKeepsManagerForReporting(t *testing.T) {
	got := ParseInstallCommand("pnpm add axios")
	if len(got) != 1 || got[0].Manager != "pnpm" {
		t.Fatalf("got %+v, want Manager pnpm", got)
	}
}

// TestEveryEcosystemBuildsAPurl is the guard against the worst class of bug this
// package can have.
//
// A candidate whose ecosystem the purl builder does not recognise gets an empty
// purl, is dropped from the request, and produces exactly the same silence as a
// package with nothing wrong with it. That is how every `composer require` went
// unchecked: the table said "packagist", which is what VDB's search flag calls
// the registry, and the purl builder wants "composer".
//
// Anything added to installVerbs is checked here, so a new ecosystem cannot be
// spelled in a way that silently drops it.
func TestEveryEcosystemBuildsAPurl(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range installVerbs {
		if seen[v.ecosystem] {
			continue
		}
		seen[v.ecosystem] = true
		if purl := cdx.BuildLocalPurl("example-pkg", "1.0.0", v.ecosystem); purl == "" {
			t.Errorf("ecosystem %q (from %v) builds no purl, so every package it names is silently dropped",
				v.ecosystem, v.argv)
		}
	}
}

// TestManifestAndCommandEcosystemsAgree keeps the two entry points naming the
// same registry the same way. A dependency added by editing a manifest and the
// same dependency added by running a command must reach VDB identically.
func TestManifestAndCommandEcosystemsAgree(t *testing.T) {
	// Left is what the manifest parser emits, right is what this table emits.
	pairs := map[string]string{
		"npm":      "npm",
		"pypi":     "pypi",
		"golang":   "golang",
		"cargo":    "cargo",
		"rubygems": "rubygems",
		"composer": "composer",
		"maven":    "maven",
		"nuget":    "nuget",
	}
	for manifestEco, commandEco := range pairs {
		a := cdx.BuildLocalPurl("example-pkg", "1.0.0", manifestEco)
		b := cdx.BuildLocalPurl("example-pkg", "1.0.0", commandEco)
		if a == "" || a != b {
			t.Errorf("manifest ecosystem %q builds %q, command ecosystem %q builds %q", manifestEco, a, commandEco, b)
		}
	}
}
