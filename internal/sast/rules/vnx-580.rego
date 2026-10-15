# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_580

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-580",
	"name": "clone() Method Without super.clone()",
	"description": "A Java class that is not final overrides clone() and builds the copy itself (a copy constructor, new ThisClass(), field-by-field copying) without calling super.clone(). A subclass that inherits this clone(), or calls super.clone() in its own, then receives an object of the parent's class, not its own: the copy silently loses the subclass's type and fields, and code that casts it fails or works on the wrong state. Reported: the declaration line of a public or protected clone() with a body (the opening brace on that line or after a throws clause on the next lines), in a class whose declaration is not final, when the body (up to its closing brace, 80 lines at most) never calls super.clone() (also when the call is split across lines). Not reported: a clone() that calls super.clone(), a clone() in a final class, record or enum, an abstract or interface clone() with no body, a clone() that only throws (CloneNotSupportedException, UnsupportedOperationException) or returns this, calls of clone() on fields or arrays, test code, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-580/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [580],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["clone", "object-model", "cwe-580"],
}

_decl_re := `^\s*(?:@\w+\s+)*(?:public|protected)\s+(?:(?:final|synchronized|static)\s+)*[\w.<>\[\]?]+\s+clone\s*\(\s*\)\s*(?:throws\s+[\w.,\s]+)?\{?\s*$`

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `//.*$`, "")

_indent(line) := count(line) - count(trim_left(line, " \t"))

_depth(lines, a, b) := sum([d |
	some k in numbers.range(a, b)
	c := _code(lines[k])
	d := count(indexof_n(c, "{")) - count(indexof_n(c, "}"))
])

# The line holding the opening brace: the declaration itself, or one of the
# next three when only a throws clause sits between them.
_open(lines, i) := i if contains(_code(lines[i]), "{")

_open(lines, i) := k if {
	not contains(_code(lines[i]), "{")
	last := min([count(lines) - 1, i + 3])
	ks := [j |
		some j in numbers.range(i + 1, last)
		contains(_code(lines[j]), "{")
	]
	count(ks) > 0
	k := min(ks)
	regex.match(`^\s*(?:throws\s+[\w.,\s]+)?\{`, _code(lines[k]))
	every m in [x | some x in numbers.range(i + 1, k); x < k] {
		regex.match(`^\s*(?:throws\s+[\w.,\s]*)?$`, _code(lines[m]))
	}
}

_body(lines, i) := concat("\n", [_code(lines[k]) | some k in numbers.range(o, e)]) if {
	o := _open(lines, i)
	last := min([count(lines) - 1, o + 80])
	ends := [k | some k in numbers.range(o, last); _depth(lines, o, k) <= 0]
	e := min(array.concat([last], ends))
}

# The nearest type declaration above with a smaller indent.
_enclosing(lines, i) := lines[j] if {
	ind := _indent(lines[i])
	cands := [k |
		some k in numbers.range(0, i - 1)
		_indent(lines[k]) < ind
		regex.match(`\b(?:class|record|enum|interface)\s+\w+`, _code(lines[k]))
		not helpers.is_comment_line(lines[k])
	]
	count(cands) > 0
	j := max(cands)
}

_final_type(decl) if regex.match(`\bfinal\b[^{(]*\bclass\b`, decl)

_final_type(decl) if regex.match(`\b(?:record|enum|interface)\s+\w+`, decl)

# Bodies that deliberately make no copy.
_no_copy(body) if regex.match(`(?s)^[^;]*\{\s*throw\s+new\s+(?:CloneNotSupportedException|UnsupportedOperationException|AssertionError)\b[^;]*;\s*\}\s*$`, body)

_no_copy(body) if regex.match(`(?s)^[^;]*\{\s*return\s+this\s*;\s*\}\s*$`, body)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "clone()")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "clone")
	regex.match(_decl_re, line)
	body := _body(lines, i)
	not regex.match(`\bsuper\s*\.\s*clone\s*\(`, body)
	not _no_copy(body)
	decl := _enclosing(lines, i)
	not _final_type(decl)
	finding := {
		"rule_id": metadata.id,
		"message": "clone() builds the copy without super.clone(): a subclass that inherits or extends it gets an instance of this class, not its own. Start from super.clone(), or make the class final",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
