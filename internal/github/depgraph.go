package github

// Dependency submission: a CycloneDX SBOM as a dependency graph snapshot,
// POST /repos/{owner}/{repo}/dependency-graph/snapshots. Needs
// `contents: write`.
//
// The SBOM is read as JSON here rather than through internal/cdx, so this
// package stays free of the scan stack. Only what the snapshot needs is read:
//
//   - components with a purl; a component without one cannot be named to
//     the dependency graph and is skipped;
//   - the vulnetix:source-file property, which groups components into the
//     manifest that declared them (internal/cdx/local.go writes it);
//   - the vulnetix:scope property, mapped to runtime or development;
//   - dependencies: the root component's dependsOn are direct, everything
//     else reached is indirect, and each component's dependsOn become its
//     dependencies in the snapshot.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Snapshot is the dependency submission API's request body.
type Snapshot struct {
	Version   int                 `json:"version"`
	SHA       string              `json:"sha"`
	Ref       string              `json:"ref"`
	Job       SnapshotJob         `json:"job"`
	Detector  SnapshotDetector    `json:"detector"`
	Scanned   string              `json:"scanned"`
	Manifests map[string]Manifest `json:"manifests"`
}

// SnapshotJob identifies the run; the correlator is what makes a later
// snapshot replace this one rather than add to it.
type SnapshotJob struct {
	Correlator string `json:"correlator"`
	ID         string `json:"id"`
	HTMLURL    string `json:"html_url,omitempty"`
}

// SnapshotDetector names the tool.
type SnapshotDetector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

// Manifest is one manifest's resolved packages.
type Manifest struct {
	Name     string                     `json:"name"`
	File     *ManifestFile              `json:"file,omitempty"`
	Resolved map[string]ResolvedPackage `json:"resolved"`
}

// ManifestFile is the manifest's path in the repository.
type ManifestFile struct {
	SourceLocation string `json:"source_location"`
}

// ResolvedPackage is one package in a manifest.
type ResolvedPackage struct {
	PackageURL   string   `json:"package_url"`
	Relationship string   `json:"relationship,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// SnapshotResult is the API's answer.
type SnapshotResult struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	Result    string `json:"result"`
	Message   string `json:"message"`
}

type cdxDoc struct {
	Metadata struct {
		Component *struct {
			BOMRef string `json:"bom-ref"`
		} `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

type cdxComponent struct {
	BOMRef     string `json:"bom-ref"`
	Purl       string `json:"purl"`
	Scope      string `json:"scope"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Components []cdxComponent `json:"components"`
}

func (c cdxComponent) prop(name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// SnapshotOptions are the run details a snapshot carries.
type SnapshotOptions struct {
	Target          Target
	Correlator      string
	JobID           string
	JobURL          string
	DetectorVersion string
	// DefaultManifest names the manifest for components with no
	// vulnetix:source-file (an SBOM this CLI did not write).
	DefaultManifest string
	Now             time.Time
}

// DefaultCorrelator is vulnetix/<workflow>/<job> from the Actions environment.
func DefaultCorrelator() string {
	wf := os.Getenv("GITHUB_WORKFLOW")
	job := os.Getenv("GITHUB_JOB")
	if wf == "" && job == "" {
		return "vulnetix/local"
	}
	return "vulnetix/" + wf + "/" + job
}

// BuildSnapshot turns a CycloneDX JSON document into a snapshot.
func BuildSnapshot(cdxJSON []byte, o SnapshotOptions) (*Snapshot, error) {
	var doc cdxDoc
	if err := json.Unmarshal(cdxJSON, &doc); err != nil {
		return nil, fmt.Errorf("read CycloneDX: %w", err)
	}
	var flat []cdxComponent
	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			flat = append(flat, c)
			walk(c.Components)
		}
	}
	walk(doc.Components)

	purlOf := map[string]string{}
	for _, c := range flat {
		if c.BOMRef != "" && c.Purl != "" {
			purlOf[c.BOMRef] = c.Purl
		}
	}
	deps := map[string][]string{}
	for _, d := range doc.Dependencies {
		deps[d.Ref] = d.DependsOn
	}
	direct := map[string]bool{}
	haveRoot := false
	if doc.Metadata.Component != nil && doc.Metadata.Component.BOMRef != "" {
		if on, ok := deps[doc.Metadata.Component.BOMRef]; ok {
			haveRoot = true
			for _, r := range on {
				direct[r] = true
			}
		}
	}

	if o.DefaultManifest == "" {
		o.DefaultManifest = "sbom.cdx.json"
	}
	manifests := map[string]Manifest{}
	for _, c := range flat {
		if c.Purl == "" {
			continue
		}
		src := c.prop("vulnetix:source-file")
		if src == "" {
			src = o.DefaultManifest
		}
		m, ok := manifests[src]
		if !ok {
			m = Manifest{Name: src, File: &ManifestFile{SourceLocation: src}, Resolved: map[string]ResolvedPackage{}}
		}
		rp := ResolvedPackage{PackageURL: c.Purl, Scope: snapshotScope(c)}
		if haveRoot {
			if direct[c.BOMRef] {
				rp.Relationship = "direct"
			} else {
				rp.Relationship = "indirect"
			}
		}
		for _, r := range deps[c.BOMRef] {
			if p := purlOf[r]; p != "" {
				rp.Dependencies = append(rp.Dependencies, p)
			}
		}
		sort.Strings(rp.Dependencies)
		key := c.Purl
		if prev, dup := m.Resolved[key]; dup {
			// The same package declared twice in one manifest: keep the
			// stronger relationship and the union of dependencies.
			if prev.Relationship == "direct" {
				rp.Relationship = "direct"
			}
			rp.Dependencies = unionSorted(prev.Dependencies, rp.Dependencies)
		}
		m.Resolved[key] = rp
		manifests[src] = m
	}

	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	corr := o.Correlator
	if corr == "" {
		corr = DefaultCorrelator()
	}
	jobID := o.JobID
	if jobID == "" {
		jobID = os.Getenv("GITHUB_RUN_ID")
	}
	if jobID == "" {
		jobID = fmt.Sprintf("%d", now.Unix())
	}
	return &Snapshot{
		Version:   0,
		SHA:       o.Target.SHA,
		Ref:       o.Target.Ref,
		Job:       SnapshotJob{Correlator: corr, ID: jobID, HTMLURL: o.JobURL},
		Detector:  SnapshotDetector{Name: "vulnetix", Version: o.DetectorVersion, URL: "https://github.com/Vulnetix/cli"},
		Scanned:   now.UTC().Format(time.RFC3339),
		Manifests: manifests,
	}, nil
}

// snapshotScope maps the scope a component was declared with to the
// dependency graph's runtime or development.
func snapshotScope(c cdxComponent) string {
	s := strings.ToLower(c.prop("vulnetix:scope"))
	if s == "" {
		s = strings.ToLower(c.Scope)
	}
	switch {
	case s == "":
		return ""
	case strings.Contains(s, "dev"), strings.Contains(s, "test"), s == "excluded", s == "build", s == "optional-dev":
		return "development"
	}
	return "runtime"
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// SubmitSnapshot posts a snapshot.
func (c *Client) SubmitSnapshot(ctx context.Context, repo string, s *Snapshot) (*SnapshotResult, error) {
	var res SnapshotResult
	if _, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/dependency-graph/snapshots", repo), s, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ManifestCount and PackageCount summarise a snapshot.
func (s *Snapshot) ManifestCount() int { return len(s.Manifests) }

func (s *Snapshot) PackageCount() int {
	n := 0
	for _, m := range s.Manifests {
		n += len(m.Resolved)
	}
	return n
}

