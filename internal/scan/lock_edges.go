package scan

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Vulnetix/vdb-sca-match/parse"
)

// This file adds dependency-tree edge builders for lock files whose parsers
// return a flat package list. Each Populate<E>LockEdges(dir) reads the dir's lock
// file and fills DepGraph.Edges (parent name → child names), mirroring
// PopulatePypiLockEdges. They are wired as offline fallbacks in the matching
// populate<E>InstalledEdges and are consumed by cdx.BuildDependencies.

// PopulateCargoLockEdges reads Cargo.lock's per-package `dependencies = [...]`.
func (g *DepGraph) PopulateCargoLockEdges(dir string) {
	if g == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.lock"))
	if err != nil {
		return
	}
	var lock struct {
		Package []struct {
			Name         string   `toml:"name"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}
	if _, derr := toml.Decode(string(data), &lock); derr != nil {
		return
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}
	for _, p := range lock.Package {
		var children []string
		for _, d := range p.Dependencies {
			// Entries are "name", "name version", or "name version (source)".
			if f := strings.Fields(d); len(f) > 0 {
				children = append(children, f[0])
			}
		}
		g.addEdges(p.Name, children)
	}
}

// PopulateGemfileLockEdges reads Gemfile.lock spec→dependency indentation
// (4-space spec, 6-space dependency) into edges.
func (g *DepGraph) PopulateGemfileLockEdges(dir string) {
	if g == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, "Gemfile.lock"))
	if err != nil {
		return
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inSpecs := false
	current := ""
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
		}
		if !inSpecs {
			continue
		}
		switch indent {
		case 4: // spec
			if f := strings.Fields(trimmed); len(f) > 0 {
				current = f[0]
			}
		case 6: // dependency of current spec
			if current != "" {
				if f := strings.Fields(trimmed); len(f) > 0 {
					g.addEdges(current, []string{f[0]})
				}
			}
		}
	}
}

// PopulateComposerLockEdges reads composer.lock per-package `require` (skipping
// php / ext-* / lib-* platform requirements).
func (g *DepGraph) PopulateComposerLockEdges(dir string) {
	if g == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, "composer.lock"))
	if err != nil {
		return
	}
	var lock struct {
		Packages []struct {
			Name    string            `json:"name"`
			Require map[string]string `json:"require"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string            `json:"name"`
			Require map[string]string `json:"require"`
		} `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}
	add := func(name string, require map[string]string) {
		var children []string
		for dep := range require {
			if dep == "php" || strings.HasPrefix(dep, "ext-") || strings.HasPrefix(dep, "lib-") {
				continue
			}
			children = append(children, dep)
		}
		g.addEdges(name, children)
	}
	for _, p := range lock.Packages {
		add(p.Name, p.Require)
	}
	for _, p := range lock.PackagesDev {
		add(p.Name, p.Require)
	}
}

// PopulateNugetLockEdges reads packages.lock.json per-package `dependencies`.
func (g *DepGraph) PopulateNugetLockEdges(dir string) {
	if g == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, "packages.lock.json"))
	if err != nil {
		return
	}
	var lock parse.NugetLockFile
	if json.Unmarshal(data, &lock) != nil {
		return
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}
	for _, byName := range lock.Dependencies {
		for name, entry := range byName {
			var children []string
			for child := range entry.Dependencies {
				children = append(children, child)
			}
			g.addEdges(name, children)
		}
	}
}

// mixLockDepRe matches a dependency entry inside a mix.lock line's deps list:
// `{:plug, "~> 1.14", [hex: :plug, …]}` → captures "plug".
var mixLockDepRe = regexp.MustCompile(`\{:([a-zA-Z0-9_]+),`)

// PopulateMixLockEdges reads mix.lock per-package dependency atoms into edges.
func (g *DepGraph) PopulateMixLockEdges(dir string) {
	if g == nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, "mix.lock"))
	if err != nil {
		return
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}
	for _, line := range strings.Split(string(data), "\n") {
		head := parse.MixLockHeadRe.FindStringSubmatch(line)
		if head == nil {
			continue
		}
		var children []string
		for _, m := range mixLockDepRe.FindAllStringSubmatch(line, -1) {
			if m[1] == "hex" || m[1] == "git" {
				continue // the wrapper {:hex, …} / {:git, …}, not a dependency
			}
			children = append(children, m[1])
		}
		g.addEdges(head[1], children)
	}
}
