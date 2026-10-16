# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1068

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1068",
	"name": "Inconsistency Between Implementation and Documented Design",
	"description": "Java: a method or constructor whose Javadoc contradicts its signature. Reported on the declaration line: a `@param name` tag naming a parameter the declaration does not have (a renamed or removed parameter whose documentation was not updated), and a `@return` tag on a method declared `void` or on a constructor. Only block tags at the start of a Javadoc line count. The declaration is read across line breaks after the Javadoc, past annotations (including ones whose arguments span several lines) and line comments, with generic type arguments and annotations removed before parameters are named. Not reported: type-parameter tags (`@param <T>`), class and record Javadoc (record components are documented with @param), parameters that are declared but not documented, matching documentation, inline mentions such as `{@code @param x}` and the inline `{@return ...}` tag, and `@param` text inside string literals. This is the one statically checkable form of the CWE: whether the behaviour matches the prose is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1068/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1068],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["javadoc-signature-mismatch", "documentation-drift", "maintainability", "java", "cwe-1068"],
}

_mods := `(?:(?:public|protected|private|static|final|abstract|synchronized|native|default|strictfp)\s+)*`

_method_re := concat("", [`^\s*`, _mods, `(?:<[^()]*>\s+)?([\w.$]+(?:<[^()]*>)?(?:\[\])*)\s+([A-Za-z_$][\w$]*)\s*\(`])

_ctor_re := concat("", [`^\s*`, _mods, `([A-Z][\w$]*)\s*\(`])

_not_types := {"return", "new", "throw", "else", "case", "yield", "assert", "package", "import", "record", "class", "interface", "enum", "await", "public", "protected", "private", "static", "final", "abstract", "synchronized", "native", "default", "strictfp"}

_keywords := {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "try", "super", "this"}

_clean(line) := regex.replace(
	regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, ""),
	`@[\w.]+(?:\s*\([^()]*\))?`, "",
)

_degeneric(t) := regex.replace(regex.replace(regex.replace(t, `<[^<>]*>`, ""), `<[^<>]*>`, ""), `<[^<>]*>`, "")

# The opening line of the Javadoc that ends at line i.
_doc_start(lines, i) := i if contains(lines[i], "/**")

_doc_start(lines, i) := max(starts) if {
	not contains(lines[i], "/**")
	starts := [k | some k in numbers.range(max([0, i - 80]), i - 1); contains(lines[k], "/**")]
	count(starts) > 0
	not _closed_between(lines, max(starts), i)
}

# A `*/` before line i means line i ends a plain block comment, not this Javadoc.
_closed_between(lines, k, i) if {
	some m in numbers.range(k, i - 1)
	contains(lines[m], "*/")
}

_skippable(line) if trim_space(_clean(line)) == ""

_skippable(line) if helpers.is_comment_line(line)

_strip_str(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_depth(line) := count(indexof_n(_strip_str(line), "(")) - count(indexof_n(_strip_str(line), ")"))

# The first code line after the Javadoc, past annotations (including ones
# whose arguments span several lines) and comments.
_decl_line(lines, i) := min(cands) if {
	n := min([count(lines) - 1, i + 16])
	cands := [j |
		some j in numbers.range(i + 1, n)
		not _skippable(lines[j])
		not startswith(trim_space(lines[j]), "@")
		sum([_depth(lines[m]) | some m in helpers.span(i + 1, j - 1)]) == 0
	]
	count(cands) > 0
}

# [return type, parameter text] of a declaration starting at line d.
_decl(lines, d) := [m[0][1], p] if {
	s := _clean(lines[d])
	m := regex.find_all_string_submatch_n(_method_re, s, 1)
	count(m) > 0
	not _not_types[m[0][1]]
	not _keywords[m[0][2]]
	p := _params(lines, d)
}

_decl(lines, d) := ["", p] if {
	s := _clean(lines[d])
	not _is_method(s)
	m := regex.find_all_string_submatch_n(_ctor_re, s, 1)
	count(m) > 0
	not _keywords[lower(m[0][1])]
	p := _params(lines, d)
}

_is_method(s) if {
	m := regex.find_all_string_submatch_n(_method_re, s, 1)
	count(m) > 0
	not _not_types[m[0][1]]
	not _keywords[m[0][2]]
}

_params(lines, d) := p if {
	txt := _degeneric(concat(" ", [_clean(l) | some l in array.slice(lines, d, min([count(lines), d + 10]))]))
	m := regex.find_all_string_submatch_n(`^[^(]*\(([^()]*)\)\s*(?:\{|throws\b|;|default\b)`, txt, 1)
	count(m) > 0
	p := m[0][1]
}

_names(p) := {n |
	some raw in split(p, ",")
	m := regex.find_all_string_submatch_n(`([A-Za-z_$][\w$]*)\s*(?:\[\s*\]\s*)*$`, trim_space(raw), 1)
	count(m) > 0
	n := m[0][1]
}

_mismatch(doc, decl) if {
	declared := _names(decl[1])
	some m in regex.find_all_string_submatch_n(`(?m)^\s*(?:/\*\*)?\s*\*?\s*@param\s+([A-Za-z_$][\w$]*)`, doc, -1)
	not declared[m[1]]
}

# Block tags start a Javadoc line; `{@return ...}` and `{@code @return}` in
# prose are not block tags.
_return_tag(doc) if regex.match(`(?m)^\s*(?:/\*\*)?\s*\*?\s*@return\b`, doc)

# @return on a void method, or on a constructor (decl[0] == "").
_mismatch(doc, decl) if {
	decl[0] == "void"
	_return_tag(doc)
}

_mismatch(doc, decl) if {
	decl[0] == ""
	_return_tag(doc)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`@(?:param|return)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	endswith(trim_space(line), "*/")
	s := _doc_start(lines, i)
	doc := concat("\n", array.slice(lines, s, i + 1))
	regex.match(`@(?:param|return)\b`, doc)
	d := _decl_line(lines, i)
	decl := _decl(lines, d)
	_mismatch(doc, decl)
	finding := {
		"rule_id": metadata.id,
		"message": "Javadoc contradicts the signature (a @param for a parameter that does not exist, or @return on a void method): update the documentation to match the implementation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d + 1,
		"snippet": lines[d],
	}
}
