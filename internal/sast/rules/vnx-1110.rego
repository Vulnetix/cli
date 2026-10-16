# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1110

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1110",
	"name": "Incomplete Design Documentation",
	"description": "A design document with a section that was never written. Design documents are Markdown files named or filed as design, architecture, ADR, RFC, proposal or threat-model documents (DESIGN.md, ARCHITECTURE.md, auth-design.md, docs/design/*, docs/design-docs/*, docs/adr/*, rfcs/*); 'design' must be a whole word of the file name, so designer-onboarding.md is not one. Reported: a section whose whole body is a placeholder (TBD, TBC, TODO, FIXME, 'To be written/determined/decided', 'Coming soon', '...', also inside an HTML comment such as '<!-- TODO: ... -->'), at the placeholder line; and a heading with no content before the next heading of the same or a higher level, or before the end of the file, at the heading. Not reported: README and other prose that is not a design document, templates (files named *template* or *skeleton*, or under a templates/ directory), setext (underlined) headings, '# key' comment lines inside YAML/TOML front matter, a placeholder word inside a sentence, a section holding only subsections, and anything inside a fenced code block.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1110/",
	"languages": [],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1110],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["documentation", "incomplete-design-documentation", "cwe-1110"],
}

_md(path) if endswith(lower(path), ".md")

_md(path) if endswith(lower(path), ".markdown")

_design_doc(path) if regex.match(`(?i)(^|/)(design|designs|design[-_]?docs?|architecture|adr|adrs|decisions|decision-records|rfc|rfcs|proposals|threat-models?)/`, path)

# 'design' as a word of the file name: DESIGN.md, auth-design.md, not designer-onboarding.md
_design_doc(path) if regex.match(`(?i)(^|/)([^/]*[-_ .])?(designs?|architecture|threat[-_ ]?model|adr[-_]?\d+)([-_ .][^/]*)?\.(md|markdown)$`, path)

# a template is placeholders on purpose
_template(path) if regex.match(`(?i)(^|/)templates?/|(^|/)[^/]*(template|skeleton)[^/]*\.(md|markdown)$`, path)

_heading_re := `^(#{1,6})[ \t]+\S`

_placeholder_re := `(?i)^[\s>*_\-]*(?:<!--\s*)?(?:tbd|tbc|todo|fixme|wip|to be (?:written|determined|decided|defined|completed|added|documented|done)|coming soon|placeholder|lorem ipsum.*|\.\.\.|…)[\s.!*_]*(?:[:\-–—]\s+.*)?(?:\s*-->)?\s*$`

_fence(line) if startswith(trim_space(line), "```")

_fence(line) if startswith(trim_space(line), "~~~")

_level(line) := count(regex.find_n(`^#+`, line, 1)[0])

findings contains finding if {
	some path, content in input.file_contents
	_md(path)
	_design_doc(path)
	not _template(path)
	regex.match(`(?m)^#{1,6}[ \t]`, content)
	lines := split(content, "\n")
	fences := [k | some k, l in lines; _fence(l)]
	some i, line in lines
	regex.match(_heading_re, line)
	not _in_fence(fences, i)
	not _in_front_matter(lines, i)
	f := _incomplete(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": f.msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": f.idx + 1,
		"snippet": lines[f.idx],
	}
}

_in_fence(fences, i) if {
	n := count([f | some f in fences; f < i])
	n % 2 == 1
}

_next_nonblank(lines, i) := k if {
	end := min([count(lines) - 1, i + 40])
	ks := [k | some k in numbers.range(i + 1, end); k > i; trim_space(lines[k]) != ""]
	count(ks) > 0
	k := ks[0]
}

# section body is only a placeholder
_incomplete(lines, i, _) := {"idx": k, "msg": "Design document section was never written: its whole body is a placeholder"} if {
	k := _next_nonblank(lines, i)
	regex.match(_placeholder_re, lines[k])
	not _section_has_more(lines, k)
}

# empty section: the next thing is a heading at the same or a higher level
_incomplete(lines, i, line) := {"idx": i, "msg": "Design document section is empty: the heading has no content before the next section"} if {
	k := _next_nonblank(lines, i)
	regex.match(_heading_re, lines[k])
	_level(lines[k]) <= _level(line)
}

# empty final section
_incomplete(lines, i, _) := {"idx": i, "msg": "Design document section is empty: the heading is the last line of the document"} if {
	i > 0
	not _next_nonblank(lines, i)
	not _any_text_after(lines, i)
}

_any_text_after(lines, i) if {
	some k in helpers.span(i + 1, count(lines) - 1)
	k > i
	trim_space(lines[k]) != ""
}

# the placeholder is followed by real prose before the next heading
_section_has_more(lines, k) if {
	j := _next_nonblank(lines, k)
	not regex.match(_heading_re, lines[j])
	not regex.match(_placeholder_re, lines[j])
}

# YAML/TOML front matter: '# key' lines there are comments, not headings
_in_front_matter(lines, i) if {
	d := trim_space(lines[0])
	d in {"---", "+++"}
	some e in numbers.range(1, min([count(lines) - 1, 60]))
	trim_space(lines[e]) == d
	i < e
	not _earlier_close(lines, e, d)
}

_earlier_close(lines, e, d) if {
	some k in numbers.range(1, e - 1)
	k < e
	trim_space(lines[k]) == d
}
