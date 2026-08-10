package lsp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/lsp/rangefix"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// sourceForKind is the Diagnostic.source per rule kind.
//
// The Problems panel groups and filters on this, so `@source:vulnetix-secrets`
// narrows to secret findings. One source for everything would make that
// impossible, and the families have genuinely different refresh cadences.
var sourceForKind = map[string]string{
	sast.KindSAST:    "vulnetix-sast",
	sast.KindSecrets: "vulnetix-secrets",
	sast.KindIAC:     "vulnetix-iac",
	sast.KindOCI:     "vulnetix-containers",
}

// SourceForKind returns the diagnostic source for a rule kind, defaulting to
// the sast source for a kind that has not been given one.
func SourceForKind(kind string) string {
	if src, ok := sourceForKind[kind]; ok {
		return src
	}
	return "vulnetix-sast"
}

// SeverityMapping controls how a Vulnetix severity becomes an LSP severity.
type SeverityMapping struct {
	// LowAsHint renders low and info findings as Hint rather than Information.
	//
	// A Hint is a subtle underline with no Problems-panel entry, which some
	// people want for style-level rules and others experience as findings
	// silently vanishing. Hence a setting, defaulting off.
	LowAsHint bool
}

// severityToLSP maps a Vulnetix severity to an LSP diagnostic severity,
// following internal/sast.SeverityToLevel so the editor and the terminal agree
// about what counts as an error.
func severityToLSP(severity string, m SeverityMapping) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return protocol.SeverityError
	case "medium":
		return protocol.SeverityWarning
	default:
		if m.LowAsHint {
			return protocol.SeverityHint
		}
		return protocol.SeverityInformation
	}
}

// DiagnosticData rides on Diagnostic.data and round-trips to the client
// untouched.
//
// It carries what a code action needs so the action can be offered without a
// second lookup, and the anchor confidence so an approximate position can be
// rendered as one rather than implying precision the finding does not have.
type DiagnosticData struct {
	FindingID        string `json:"findingId"`
	Tool             string `json:"tool"`
	RuleID           string `json:"ruleId,omitempty"`
	AnchorConfidence string `json:"anchorConfidence,omitempty"`
	FixAvailable     bool   `json:"fixAvailable,omitempty"`
	Suppressible     bool   `json:"suppressible"`
}

// ToDiagnostic converts one Rego finding into an LSP diagnostic against the
// current text of the document it belongs to.
//
// Returns false when the finding cannot be placed in the current text, which
// happens when the user has edited above it since the scan. Dropping is
// deliberate: a stale finding rendered confidently on the wrong line is worse
// than a missing one, and the document is re-analysed moments later anyway.
func ToDiagnostic(f sast.Finding, docText string, m SeverityMapping) (protocol.Diagnostic, bool) {
	lines := rangefix.SplitLines(docText)

	kind := ""
	if f.Metadata != nil {
		kind = f.Metadata.Kind
	}

	placed, ok := rangefix.Columns(lines, f.StartLine, f.EndLine, rangefix.Options{
		Kind:    kind,
		Snippet: f.Snippet,
	})
	if !ok {
		return protocol.Diagnostic{}, false
	}

	diag := protocol.Diagnostic{
		Range: protocol.Range{
			Start: protocol.Position{Line: placed.Range.Start.Line, Character: placed.Range.Start.Character},
			End:   protocol.Position{Line: placed.Range.End.Line, Character: placed.Range.End.Character},
		},
		Severity: severityToLSP(f.Severity, m),
		Code:     f.RuleID,
		Source:   SourceForKind(kind),
		Message:  message(f),
	}

	// A code description turns the rule id in the Problems panel into a link.
	// Omitted rather than guessed when the rule declares no help URI, because a
	// link to a 404 is worse than no link.
	if f.Metadata != nil && f.Metadata.HelpURI != "" {
		diag.CodeDescription = &protocol.CodeDescription{Href: f.Metadata.HelpURI}
	}

	data := DiagnosticData{
		FindingID:        f.Fingerprint,
		Tool:             kindToTool(kind),
		RuleID:           f.RuleID,
		AnchorConfidence: string(placed.Confidence),
		Suppressible:     true,
	}
	if raw, err := json.Marshal(data); err == nil {
		diag.Data = raw
	}

	return diag, true
}

// message renders the human-readable text, appending the rule name when it adds
// something the message does not already say.
func message(f sast.Finding) string {
	msg := strings.TrimSpace(f.Message)
	if msg == "" && f.Metadata != nil {
		msg = strings.TrimSpace(f.Metadata.Name)
	}
	if msg == "" {
		msg = f.RuleID
	}
	return msg
}

// kindToTool maps a rule kind to the tool name used in the finding model, where
// the OCI kind is presented as "container" because that is what a user calls it.
func kindToTool(kind string) string {
	switch kind {
	case sast.KindOCI:
		return "container"
	case "":
		return sast.KindSAST
	default:
		return kind
	}
}

// GroupByURI converts findings into diagnostics grouped by document URI.
//
// docs maps a repository-relative path to that document's current text. A
// finding whose file is not in docs is skipped: without the current text there
// is no way to compute a range that matches what the user is looking at, and
// guessing produces an underline in the wrong place.
//
// Every URI in docs appears in the result, including those with no findings.
// That is required rather than an optimisation: publishDiagnostics replaces the
// whole list for a URI, so a file whose last finding was just fixed needs an
// explicit empty list or the stale diagnostic stays on screen forever.
func GroupByURI(findings []sast.Finding, docs map[string]docText, m SeverityMapping) map[string][]protocol.Diagnostic {
	out := make(map[string][]protocol.Diagnostic, len(docs))
	for _, d := range docs {
		out[d.URI] = []protocol.Diagnostic{}
	}

	for _, f := range findings {
		doc, ok := docs[f.ArtifactURI]
		if !ok {
			continue
		}
		diag, ok := ToDiagnostic(f, doc.Text, m)
		if !ok {
			continue
		}
		out[doc.URI] = append(out[doc.URI], diag)
	}
	return out
}

// docText pairs a document's URI with its current text.
type docText struct {
	URI  string
	Text string
}

// CountBySeverity summarises diagnostics for the status bar.
func CountBySeverity(diags map[string][]protocol.Diagnostic) map[string]int {
	counts := map[string]int{}
	for _, list := range diags {
		for _, d := range list {
			switch d.Severity {
			case protocol.SeverityError:
				counts["error"]++
			case protocol.SeverityWarning:
				counts["warning"]++
			default:
				counts["info"]++
			}
		}
	}
	return counts
}

// DescribeCounts renders a count summary for a log line.
func DescribeCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "no findings"
	}
	return fmt.Sprintf("%d error(s), %d warning(s), %d note(s)",
		counts["error"], counts["warning"], counts["info"])
}
