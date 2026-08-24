// Package ghasetup wires third-party security scanners into a repository's
// GitHub Actions workflows.
//
// The catalog is the single source of truth: `vulnetix gha setup` renders
// workflow jobs from it, and the published documentation examples are generated
// from it too. A tool documented on the website is therefore, by construction,
// the same job the command writes and the same job that runs in production.
package ghasetup

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed catalog/tools.json
var catalogJSON []byte

//go:embed catalog/extra_tools.json
var extraCatalogJSON []byte

// Catalog is the parsed tool catalog.
type Catalog struct {
	Version int    `json:"version"`
	Tools   []Tool `json:"tools"`
}

// Tool is one scanner: the job that runs it and the artifact it leaves behind.
type Tool struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	JobName     string   `json:"jobName"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Artifact    string   `json:"artifact"`
	Paths       []string `json:"paths"`
	Note        string   `json:"note,omitempty"`

	// TimeoutMinutes overrides DefaultJobTimeoutMinutes for this tool.
	//
	// Set it only where the measured runtime says the default is wrong: too
	// tight and a legitimate slow scan is killed, too loose and a hung one
	// holds a runner until GitHub's six-hour ceiling. Zero means "use the
	// default", which is the right answer for almost every scanner.
	TimeoutMinutes int `json:"timeoutMinutes,omitempty"`

	Detect Detect `json:"detect"`
	Steps  []Step `json:"steps"`
}

// Detect says when `gha setup --detect` should pick a tool for a repository.
//
// Every recipe already refuses to run against a tree it has nothing to say
// about ("no go.mod found; skipping gosec"), so a wrong guess here costs a
// no-op job rather than a bad result. What it buys is a workflow that names
// only the scanners this repository can actually feed, which is the difference
// between reading a run and scrolling past forty skipped jobs.
type Detect struct {
	// Always marks a tool that works on any repository: the SBOM producers,
	// the secret scanners, the multi-language SAST engines.
	Always bool `json:"always,omitempty"`

	// Files are basenames or directory names that must exist somewhere in the
	// tree. A match on any one of them selects the tool.
	Files []string `json:"files,omitempty"`

	// Extensions are file suffixes, matched the same way.
	Extensions []string `json:"extensions,omitempty"`

	// Manual keeps a tool out of --detect entirely. These are the ones that
	// need something the repository cannot supply: a licence key (Snyk), or a
	// live target the operator must nominate (ZAP, Nuclei). Selecting one by
	// name still works.
	Manual bool `json:"manual,omitempty"`
}

// Step is one workflow step. Exactly one of Uses or Run is set.
type Step struct {
	Name string            `json:"name,omitempty"`
	ID   string            `json:"id,omitempty"`
	Uses string            `json:"uses,omitempty"`
	Run  string            `json:"run,omitempty"`
	With map[string]any    `json:"with,omitempty"`
	Env  map[string]string `json:"env,omitempty"`
}

// Load parses the embedded catalog.
func Load() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(catalogJSON, &c); err != nil {
		return nil, fmt.Errorf("parse tool catalog: %w", err)
	}
	var extra struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(extraCatalogJSON, &extra); err != nil {
		return nil, fmt.Errorf("parse extra tool catalog: %w", err)
	}
	c.Tools = append(c.Tools, extra.Tools...)
	if len(c.Tools) == 0 {
		return nil, fmt.Errorf("tool catalog is empty")
	}
	return &c, nil
}

// Find returns the tool with this id, matched case-insensitively.
func (c *Catalog) Find(id string) (*Tool, bool) {
	want := strings.ToLower(strings.TrimSpace(id))
	for i := range c.Tools {
		if strings.ToLower(c.Tools[i].ID) == want {
			return &c.Tools[i], true
		}
	}
	return nil, false
}

// IDs returns every tool id, sorted.
func (c *Catalog) IDs() []string {
	out := make([]string, 0, len(c.Tools))
	for _, t := range c.Tools {
		out = append(out, t.ID)
	}
	sort.Strings(out)
	return out
}

// Suggest returns catalog ids similar to the given one, for a "did you mean"
// on a typo or on a name the catalog spells differently ("trivy" is split into
// trivy-fs and trivy-config).
func (c *Catalog) Suggest(id string) []string {
	want := strings.ToLower(strings.TrimSpace(id))
	if want == "" {
		return nil
	}
	var out []string
	for _, t := range c.Tools {
		lid := strings.ToLower(t.ID)
		if strings.Contains(lid, want) || strings.Contains(want, lid) ||
			strings.Contains(strings.ToLower(t.Name), want) {
			out = append(out, t.ID)
		}
	}
	sort.Strings(out)
	return out
}
