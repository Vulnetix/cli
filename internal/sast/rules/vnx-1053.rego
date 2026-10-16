# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1053

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1053",
	"name": "Missing Documentation for Design",
	"description": "CWE-1053 (missing design documentation) has no code shape of its own, so this rule reports the one concrete signal source code carries: a Java or Python comment in which the author records that the design or architecture is not documented. That is a TODO/FIXME/XXX/TBD marker naming the design or architecture together with documenting, explaining or describing it (\"// TODO: document the design of this cache\", \"# FIXME: explain the architecture of the retry pipeline\", \"TODO(ops): write up the design rationale\"), or a statement that the design documentation is missing or pending (\"no design doc yet\", \"undocumented design\", \"design doc: TBD\", \"the architecture here is undocumented\"). Not reported: a comment that points at documentation which exists (\"see the design doc at docs/design/cache.md\", an ADR number, a URL) or says no design doc change is needed, a TODO about documenting a parameter or a function, a TODO to design something (the work, not its documentation), the same words in a string literal or in code, and files in other languages. Classes or modules without doc comments are deliberately not reported: absence of a docstring is not evidence that a design is undocumented.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1053/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1053],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-design-docs", "documentation-debt", "comments", "cwe-1053"],
}

_gate := `(?i)design|architecture`

# A marker naming the design/architecture and the act of documenting it.
_todo_re := `(?i)\b(?:TODO|FIXME|XXX|TBD)\b.{0,60}?\b(?:design|architecture|architectural)\b`

_doc_re := `(?i)\b(?:doc|docs|document|documented|documenting|documentation|explain|explained|describe|described|write[- ]?(?:up|down)|rationale|adr)\b`

# A statement that the design documentation is absent or pending.
_missing_re := `(?i)\bundocumented\s+(?:design|architecture)\b|\b(?:undocumented|no|missing|lacks?|without)\s+(?:the\s+)?(?:design|architecture)\s+(?:doc|docs|document|documentation|notes?|description)\b|\b(?:design|architecture)\s+(?:doc|docs|documentation)\s*(?::|-|is|are)?\s*(?:TBD|TODO|missing|pending|to\s+be\s+written|not\s+(?:yet\s+)?written|coming)\b`

# The comment text of a line: the whole line when it is a comment, else the
# text after a trailing // (Java) or # (Python) that is outside a string.
_comment_text(line, _) := line if helpers.is_comment_line(line)

_comment_text(line, path) := m[0][1] if {
	not helpers.is_comment_line(line)
	endswith(path, ".java")
	m := regex.find_all_string_submatch_n(`^[^"']*?//(.*)$`, line, 1)
	count(m) > 0
}

_comment_text(line, path) := m[0][1] if {
	not helpers.is_comment_line(line)
	endswith(path, ".py")
	m := regex.find_all_string_submatch_n(`^[^"']*?#(.*)$`, line, 1)
	count(m) > 0
}

# "the architecture here is undocumented", "design is not documented yet".
_undoc_re := `(?i)\b(?:design|architecture)\b.{0,30}?\b(?:is|are)\s+(?:still\s+)?(?:undocumented|not\s+(?:yet\s+)?documented)\b`

# The comment points at documentation that exists ("see the design doc at
# docs/design/cache.md", "ADR-0007", a URL), or says no doc change is needed.
_points_to_doc(text) if regex.match(`(?i)\bsee\b|https?://|\bADR-?\d+|[\w.-]+/[\w./-]+\.(?:md|rst|adoc|txt)\b`, text)

_points_to_doc(text) if regex.match(`(?i)\b(?:design|architecture)\s+(?:doc|docs|documentation)\s+(?:changes?|updates?|needed|required|review|approved)\b`, text)

_marker(text) if {
	regex.match(_todo_re, text)
	regex.match(_doc_re, text)
	not _points_to_doc(text)
}

_marker(text) if {
	regex.match(_missing_re, text)
	not _points_to_doc(text)
}

_marker(text) if regex.match(_undoc_re, text)

_lang_ok(path) if endswith(path, ".java")

_lang_ok(path) if endswith(path, ".py")

findings contains finding if {
	some path, content in input.file_contents
	_lang_ok(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	text := _comment_text(line, path)
	_marker(text)
	finding := {
		"rule_id": metadata.id,
		"message": "Comment records that this design is not documented; write down the design, its assumptions and its trust boundaries (CWE-1053)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
