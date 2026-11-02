package license

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"github.com/Vulnetix/vdb-sca-match/sarif"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// BuildLog returns the analysis as a GitHub-ready SARIF log with the code
// scanning category vulnetix/license/: rules carry security-severity and
// security tags, and each result sits on the manifest line that declares the
// package. A result whose package has no manifest (a conflict between two
// packages found only in a lockfile, say) is placed on the manifest of the
// first package that names it, or left without a location.
//
// The partial fingerprint hashes rule, package and manifest, never the
// version or the manifest line, so bumping a dependency that is still in
// breach keeps the same alert.
func BuildLog(result *AnalysisResult, root, toolVersion string) *sarif.Log {
	findings, rules := BuildSARIFFromAnalysis(result)

	sourceOf := map[string]string{}
	if result != nil {
		for _, p := range result.Packages {
			if p.SourceFile != "" && sourceOf[p.PackageName] == "" {
				sourceOf[p.PackageName] = p.SourceFile
			}
		}
	}
	descriptors := make([]sarif.ReportingDescriptor, 0, len(rules))
	for _, r := range rules {
		d := sarif.ReportingDescriptor{
			ID:               r.ID,
			Name:             r.Name,
			ShortDescription: &sarif.Message{Text: r.Name},
			Properties: sarif.PropertyBag{
				"severity": r.Severity,
				"tags":     sast.SecurityTags(r.Tags, nil),
			},
		}
		if ss := sast.SecuritySeverity(r.Severity); ss != "" {
			d.Properties["security-severity"] = ss
		}
		descriptors = append(descriptors, d)
	}

	lines := sast.NewManifestLines(root)
	results := make([]sarif.Result, 0, len(findings))
	for _, f := range findings {
		res := sarif.Result{
			RuleID:  f.RuleID,
			Level:   f.Level,
			Message: sarif.Message{Text: f.Message},
			Properties: sarif.PropertyBag{
				"severity":      f.Severity,
				"vulnetix/kind": "license",
			},
		}
		if f.PackagePurl != "" {
			res.Properties["vulnetix/purl"] = f.PackagePurl
		}
		if f.Fingerprint != "" {
			res.Fingerprints = map[string]string{"vulnetix/v1": f.Fingerprint}
		}
		file, name := f.ArtifactURI, ""
		if src, ok := sourceOf[f.ArtifactURI]; ok {
			// A conflict names packages, not files.
			file, name = src, f.ArtifactURI
		} else if result != nil {
			for _, lf := range result.Findings {
				if lf.Package.SourceFile == f.ArtifactURI && f.Message == lf.Description {
					name = lf.Package.PackageName
					break
				}
			}
		}
		res.PartialFingerprints = map[string]string{"primaryLocationLineHash": versionless(f.RuleID, name, file)}
		if file != "" && looksLikeFile(file) {
			line := lines.Find(file, name)
			if line <= 0 {
				line = 1
			}
			res.Locations = []sarif.Location{{PhysicalLocation: &sarif.PhysicalLocation{
				ArtifactLocation: &sarif.ArtifactLocation{URI: filepath.ToSlash(file)},
				Region:           &sarif.Region{StartLine: line},
			}}}
		}
		results = append(results, res)
	}

	return &sarif.Log{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarif.Run{{
			Tool: sarif.Tool{Driver: sarif.ToolComponent{
				Name:           "vulnetix",
				Version:        toolVersion,
				InformationURI: "https://vulnetix.com",
				Rules:          descriptors,
			}},
			Results:           results,
			AutomationDetails: &sarif.RunAutomationDetails{ID: sast.AutomationID("license")},
		}},
	}
}

// looksLikeFile tells a manifest path from a package name or purl.
func looksLikeFile(s string) bool {
	if len(s) > 4 && s[:4] == "pkg:" {
		return false
	}
	return filepath.Ext(s) != "" || filepath.Base(s) != s
}

func versionless(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8]) + ":1"
}
