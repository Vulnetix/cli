# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1074

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1074",
	"name": "Class with Excessively Deep Inheritance",
	"description": "A Java class whose chain of extends clauses, resolved across every Java file in the project by simple class name, is seven or more levels deep: seven extends edges, every class on the way declared in the project and the last parent possibly a library class (java.lang.Object is not counted). Headers may carry annotations and put the extends clause on the next line. Each level adds behaviour a reader must hold in mind and an override that can silently change what the base classes rely on, which is how deep hierarchies hide defects. The finding is on the class declaration. Not reported: chains of six edges or fewer (ancestors above a library class cannot be seen and are not counted), interfaces and implements clauses, generic bounds (class Box<T extends Number>), chains that loop back on a name (two classes with the same simple name in different packages), test sources, and class headers inside comments (line or block) or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1074/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1074],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["deep-inheritance", "cwe-1074"],
}

_annots := `(?:@[\w.]+(?:\([^)]*\))?\s+)*`

_mods := `(?:(?:public|protected|private|abstract|final|static|sealed|non-sealed|strictfp)\s+)*`

# `class Name<generics> extends pkg.Parent<...>`, after any annotations; the
# extends clause may be on the next line.
_class_re := concat("", [`^\s*`, _annots, _mods, `class\s+([A-Za-z_$][\w$]*)(?:\s*<.*?>)?\s+extends\s+([\w$.]+)`])

_last(name) := parts[count(parts) - 1] if parts := split(name, ".")

# Comments are removed before edges are read, so a class header quoted in a
# block comment or a // line adds no edge.
_strip_comments(content) := regex.replace(regex.replace(content, `(?s)/\*.*?\*/`, ""), `(?m)//.*$`, "")

_edges contains [m[1], p] if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "extends")
	code := _strip_comments(content)
	some m in regex.find_all_string_submatch_n(concat("", ["(?m)", _class_re]), code, -1)
	p := _last(m[2])
	p != m[1]
	p != "Object"
}

_parents[c] contains p if some [c, p] in _edges

# Seven extends edges; every class but the last parent is declared in the project.
_deep(c) if {
	some p1 in _parents[c]
	some p2 in _parents[p1]
	some p3 in _parents[p2]
	some p4 in _parents[p3]
	some p5 in _parents[p4]
	some p6 in _parents[p5]
	some p7 in _parents[p6]
	count({c, p1, p2, p3, p4, p5, p6, p7}) == 8
}

# The line sits inside a /* ... */ block opened at most 60 lines above.
_in_block_comment(lines, i) if {
	i > 0
	opens := [k | some k in numbers.range(max([0, i - 60]), i - 1); contains(_nostr(lines[k]), "/*")]
	count(opens) > 0
	o := opens[count(opens) - 1]
	not contains(regex.replace(_nostr(lines[o]), `^.*?/\*`, ""), "*/")
	not _closed_between(lines, o, i)
}

_closed_between(lines, o, i) if {
	some k in numbers.range(o + 1, i)
	k < i
	contains(lines[k], "*/")
}

# String literals blanked, so "/*" in a servlet mapping opens no comment.
_nostr(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "extends")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "class")
	not helpers.is_comment_line(line)
	header := concat(" ", array.slice(lines, i, min([i + 2, count(lines)])))
	m := regex.find_all_string_submatch_n(_class_re, header, 1)[0]
	regex.match(concat("", [`\bclass\s+`, m[1], `\b`]), line)
	_deep(m[1])
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Class %s sits seven or more levels deep in a project inheritance chain; prefer composition or flatten the hierarchy", [m[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
