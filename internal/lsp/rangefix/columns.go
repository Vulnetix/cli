// Package rangefix turns a line-only finding into an editor range.
//
// The SARIF writer emits StartLine, EndLine and a snippet, and never a column
// (internal/sast/sarif.go). SARIF's Region type supports columns; Vulnetix does
// not populate them, because the rule engine reports line granularity.
//
// An editor needs a character range. Without one every finding underlines the
// whole line, the lightbulb anchors to the whole line, and "suppress this
// secret" reads as though it applies to the entire statement.
//
// Columns are synthesized here rather than fixed in the SARIF writer on
// purpose. That writer's output feeds vdb-api ingestion, GitHub code scanning
// and the SARIF round-trip golden tests, so changing it has a blast radius far
// beyond the editor. Columns are also fingerprint-neutral: a fingerprint is
// sha256(RuleID \x00 ArtifactURI \x00 StartLine), so nothing downstream depends
// on their absence.
package rangefix

import (
	"strings"
	"unicode/utf8"
)

// Confidence describes how the range was derived, so the editor can render an
// approximate position differently from an exact one instead of implying a
// precision it does not have.
type Confidence string

const (
	// ConfidenceExact means the snippet was found on the line and the range
	// covers it.
	ConfidenceExact Confidence = "exact"
	// ConfidenceSnippet means the snippet matched after normalisation, for
	// instance ignoring leading whitespace differences.
	ConfidenceSnippet Confidence = "snippet"
	// ConfidenceLine means no snippet match was possible and the range covers
	// the line's non-whitespace content.
	ConfidenceLine Confidence = "line"
)

// Position is a zero-based line and a zero-based character offset measured in
// UTF-16 code units, matching the LSP default position encoding.
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range is a half-open interval between two Positions.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Result is a derived range plus how much to trust it.
type Result struct {
	Range      Range
	Confidence Confidence
}

// Options tune the derivation for a particular finding.
type Options struct {
	// Kind is the rule kind ("secrets", "sast", "iac", "oci"). Secrets get an
	// extra narrowing pass; see narrowToSecretValue.
	Kind string
	// Snippet is the finding's captured source text. May be empty, and may span
	// several lines when --snippet-context was used.
	Snippet string
}

// Columns derives an editor range for a finding that carries only line numbers.
//
// doc is the CURRENT text of the document, split into lines, which is not
// necessarily the text the finding was produced from: the user may have typed
// since. startLine and endLine are 1-based, as SARIF reports them.
//
// Returns ok=false when the finding cannot be placed, which callers must treat
// as "drop this diagnostic" rather than "clamp it somewhere". A stale finding
// pointing confidently at the wrong line is worse than a missing one; the
// document is rescanned moments later anyway.
func Columns(doc []string, startLine, endLine int, opts Options) (Result, bool) {
	// 1. Bounds. Out of range means the document changed underneath the
	//    finding. Drop rather than clamp.
	if startLine < 1 || startLine > len(doc) {
		return Result{}, false
	}
	if endLine < startLine {
		endLine = startLine
	}
	if endLine > len(doc) {
		endLine = len(doc)
	}

	startText := doc[startLine-1]
	endText := doc[endLine-1]

	// 2 and 3. Snippet matching, single then multi line.
	if r, conf, ok := matchSnippet(doc, startLine, endLine, opts.Snippet); ok {
		if opts.Kind == "secrets" {
			r = narrowToSecretValue(doc, r)
		}
		return Result{Range: r, Confidence: conf}, true
	}

	// 5. Whitespace-trim fallback: the line's content without its indentation.
	startCol, endCol := trimmedSpan(startText, endText, startLine == endLine)

	r := Range{
		Start: Position{Line: startLine - 1, Character: utf16Len(startText[:startCol])},
		End:   Position{Line: endLine - 1, Character: utf16Len(endText[:endCol])},
	}
	if opts.Kind == "secrets" {
		r = narrowToSecretValue(doc, r)
	}
	return Result{Range: r, Confidence: ConfidenceLine}, true
}

// matchSnippet locates the finding's captured text within the document.
func matchSnippet(doc []string, startLine, endLine int, snippet string) (Range, Confidence, bool) {
	if strings.TrimSpace(snippet) == "" {
		return Range{}, "", false
	}

	snippetLines := nonBlankLines(snippet)
	if len(snippetLines) == 0 {
		return Range{}, "", false
	}

	startText := doc[startLine-1]
	first := strings.TrimSpace(snippetLines[0])

	// Single-line snippet: find it on the start line.
	if len(snippetLines) == 1 {
		if i := strings.Index(startText, first); i >= 0 {
			return Range{
				Start: Position{Line: startLine - 1, Character: utf16Len(startText[:i])},
				End:   Position{Line: startLine - 1, Character: utf16Len(startText[:i+len(first)])},
			}, ConfidenceExact, true
		}
		return Range{}, "", false
	}

	// Multi-line: the first non-blank snippet line fixes the start column and
	// the last fixes the end column. Both must be found, or the snippet no
	// longer corresponds to this text and guessing would be worse than falling
	// back to the whole line.
	last := strings.TrimSpace(snippetLines[len(snippetLines)-1])
	endText := doc[endLine-1]

	startIdx := strings.Index(startText, first)
	endIdx := strings.Index(endText, last)
	if startIdx < 0 || endIdx < 0 {
		return Range{}, "", false
	}

	return Range{
		Start: Position{Line: startLine - 1, Character: utf16Len(startText[:startIdx])},
		End:   Position{Line: endLine - 1, Character: utf16Len(endText[:endIdx+len(last)])},
	}, ConfidenceSnippet, true
}

// secretSeparators are the assignment forms a credential appears after, longest
// first so that ":=" and "=>" win over ":" and "=".
var secretSeparators = []string{":=", "=>", "::", "=", ":"}

// narrowToSecretValue moves the start of a secret finding past the assignment,
// so the underline sits on the credential rather than the whole statement.
//
// VS Code anchors the lightbulb to the diagnostic range, so a whole-statement
// range makes "suppress this secret" read as though it applies to the
// statement. It also means the underline covers the variable name, which is
// usually the part the reader needs to see intact.
//
// Only applied to single-line ranges: a multi-line secret is a key block, where
// the whole span is the point.
func narrowToSecretValue(doc []string, r Range) Range {
	if r.Start.Line != r.End.Line {
		return r
	}
	line := doc[r.Start.Line]

	startByte, ok := byteOffset(line, r.Start.Character)
	if !ok {
		return r
	}
	endByte, ok := byteOffset(line, r.End.Character)
	if !ok || endByte <= startByte {
		return r
	}

	span := line[startByte:endByte]

	best := -1
	bestLen := 0
	for _, sep := range secretSeparators {
		if i := strings.Index(span, sep); i >= 0 && (best < 0 || i < best) {
			best, bestLen = i, len(sep)
		}
	}
	if best < 0 {
		return r
	}

	// Step past the separator, then any whitespace and one opening quote.
	cursor := startByte + best + bestLen
	for cursor < endByte && (line[cursor] == ' ' || line[cursor] == '\t') {
		cursor++
	}
	if cursor < endByte && (line[cursor] == '"' || line[cursor] == '\'' || line[cursor] == '`') {
		cursor++
	}

	// A separator at the very end leaves nothing to point at; keep the original.
	if cursor >= endByte {
		return r
	}

	r.Start.Character = utf16Len(line[:cursor])
	return r
}

// trimmedSpan returns byte offsets covering a line's non-whitespace content.
//
// For an entirely blank line it returns 0,0, which renders as a zero-width
// range at the start of the line. VS Code draws that as a whole-line squiggle,
// which is the right outcome for a finding about a line with nothing on it.
func trimmedSpan(startText, endText string, sameLine bool) (int, int) {
	start := len(startText) - len(strings.TrimLeft(startText, " \t"))
	if start >= len(startText) {
		start = 0
	}

	end := len(strings.TrimRight(endText, " \t\r\n"))
	if sameLine && end <= start {
		// Blank or whitespace-only line.
		return 0, 0
	}
	if end < 0 {
		end = 0
	}
	return start, end
}

// nonBlankLines splits a snippet and drops blank lines from both ends, since
// --snippet-context pads with surrounding context.
func nonBlankLines(snippet string) []string {
	raw := strings.Split(strings.ReplaceAll(snippet, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// utf16Len counts the UTF-16 code units in s.
//
// LSP measures Position.Character in UTF-16 code units by default, and the
// server advertises positionEncoding "utf-16". Go strings are UTF-8 bytes, so
// reporting a byte offset puts the range in the wrong place on any line
// containing a character outside the Basic Multilingual Plane: emoji are two
// UTF-16 units and four UTF-8 bytes, CJK are one unit and three bytes.
//
// An invalid byte decodes as RuneError with width 1, which is what the editor's
// own decoder will do with it too.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// byteOffset converts a UTF-16 character offset back to a byte offset in s.
// Reports false when the offset falls beyond the end of the string or inside a
// surrogate pair.
func byteOffset(s string, char int) (int, bool) {
	if char <= 0 {
		return 0, true
	}
	units := 0
	for i, r := range s {
		if units == char {
			return i, true
		}
		if r > 0xFFFF {
			units += 2
		} else {
			units++
		}
		if units > char {
			// Landed inside a surrogate pair.
			return i, false
		}
	}
	if units == char {
		return len(s), true
	}
	return len(s), false
}

// SplitLines splits document text into lines for Columns.
//
// Handles LF, CRLF and a leading byte-order mark. The BOM is stripped from the
// first line only: left in place it shifts every column on line 1 by one, which
// is the kind of off-by-one that only shows up on Windows-authored files.
func SplitLines(text string) []string {
	text = strings.TrimPrefix(text, "\uFEFF")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// ValidUTF8 reports whether text can be positioned reliably. Invalid UTF-8
// makes any character offset ambiguous, so callers may prefer whole-line ranges.
func ValidUTF8(text string) bool { return utf8.ValidString(text) }
