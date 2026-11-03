package report

// SCA findings as SARIF, for GitHub code scanning.
//
// One rule per advisory, one result per package that the advisory counts
// against (affected or unverified; ruled-out advisories are left out, as the
// views leave them out). The result sits on the manifest line that declares the
// package, so the alert opens on the line to change.
//
// The fingerprint leaves out the version. A primaryLocationLineHash taken from
// the manifest line would change when the version on that line is bumped,
// which would close the alert and open a new one on every bump that does not
// fix it. Hashing ecosystem, name, advisory and manifest instead keeps it the
// same alert until a scan stops reporting it.

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Vulnetix/vdb-sca-match/sarif"
	"github.com/vulnetix/cli/v4/internal/sast"
)

// BuildSARIF returns the report's SCA findings as a single-run SARIF log with
// the code scanning category vulnetix/sca/. root is the scan root the package
// sources are relative to; it is read only to find the declaring line.
func BuildSARIF(r Report, root, toolVersion string) *sarif.Log {
	rules := map[string]*sarif.ReportingDescriptor{}
	var ruleOrder []string
	results := []sarif.Result{}
	lines := sast.NewManifestLines(root)

	for _, p := range r.Packages {
		for _, a := range p.Advisories {
			if a.ID == "" {
				continue
			}
			sev := strings.ToLower(a.Severity)
			if _, ok := rules[a.ID]; !ok {
				d := &sarif.ReportingDescriptor{
					ID:               a.ID,
					Name:             a.ID,
					ShortDescription: &sarif.Message{Text: a.ID + " in a dependency"},
					HelpURI:          "https://www.vulnetix.com/vulnerability/" + a.ID,
					Properties: sarif.PropertyBag{
						"severity": sev,
						"tags":     sast.SecurityTags([]string{"sca", "dependency"}, nil),
					},
				}
				if ss := securitySeverityFor(a); ss != "" {
					d.Properties["security-severity"] = ss
				}
				rules[a.ID] = d
				ruleOrder = append(ruleOrder, a.ID)
			}

			msg := a.ID + " affects " + p.Label()
			if p.Fix.Target != "" {
				msg += "; upgrade to " + p.Fix.Target
			}
			res := sarif.Result{
				RuleID:  a.ID,
				Level:   sast.SeverityToLevel[sev],
				Message: sarif.Message{Text: msg},
				PartialFingerprints: map[string]string{
					"primaryLocationLineHash": versionlessHash(p, a.ID),
				},
				Properties: sarif.PropertyBag{
					"severity":            sev,
					"vulnetix/kind":       "sca",
					"vulnetix/package":    p.Name,
					"vulnetix/version":    p.Version,
					"vulnetix/ecosystem":  p.Ecosystem,
					"vulnetix/direct":     p.Direct,
					"vulnetix/verdict":    string(a.Verdict.Verdict),
					"vulnetix/fixVersion": p.Fix.Target,
				},
			}
			if res.Level == "" {
				res.Level = "warning"
			}
			if p.Source != "" {
				loc := sarif.Location{PhysicalLocation: &sarif.PhysicalLocation{
					ArtifactLocation: &sarif.ArtifactLocation{URI: filepath.ToSlash(p.Source)},
				}}
				if n := lines.Find(p.Source, p.Name); n > 0 {
					loc.PhysicalLocation.Region = &sarif.Region{StartLine: n}
				} else {
					loc.PhysicalLocation.Region = &sarif.Region{StartLine: 1}
				}
				res.Locations = []sarif.Location{loc}
			}
			results = append(results, res)
		}
	}

	sort.Strings(ruleOrder)
	descriptors := make([]sarif.ReportingDescriptor, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		descriptors = append(descriptors, *rules[id])
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
			AutomationDetails: &sarif.RunAutomationDetails{ID: sast.AutomationID("sca")},
		}},
	}
}

// securitySeverityFor prefers the advisory's own CVSS score, which is what
// GitHub's security-severity is, and falls back to the severity band.
func securitySeverityFor(a Advisory) string {
	if a.CVSS > 0 && a.CVSS <= 10 {
		return strconv.FormatFloat(a.CVSS, 'f', 1, 64)
	}
	return sast.SecuritySeverity(a.Severity)
}

// versionlessHash is the fingerprint: a stable hash of what the finding is
// about, without the installed version, in the "hex:1" form GitHub expects.
func versionlessHash(p Package, advisory string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join([]string{
		p.Ecosystem, p.Name, advisory, filepath.ToSlash(p.Source),
	}, "\x00"))))
	return hex.EncodeToString(sum[:8]) + ":1"
}
