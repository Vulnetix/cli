# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_581

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-581",
	"name": "Object Model Violation: Just One of Equals and Hashcode Defined",
	"description": "A Java or Kotlin class overrides equals(Object) without hashCode(), or hashCode() without equals(Object), so two objects the class calls equal can hash differently (or the reverse): HashMap, HashSet and caches then miss entries, store duplicates, or fail to find a key that is present, which can defeat de-duplication, permission sets and lookups keyed by the object. The pairing is judged per class, so an inner or nested class that defines only one is reported even when the outer class defines both. Reported: the line declaring the lone method, public boolean equals(Object) / public int hashCode() in Java and override fun equals(other: Any?) / override fun hashCode() in Kotlin, also with the parameter list broken onto the next line. Not reported: a class that defines both, a Kotlin data class or Java record (the compiler generates the other method over the same components), an equals overload with another parameter type (equals(Point p)), calls of hashCode() or equals() on other objects, test code, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-581/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [581],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["equals-hashcode", "object-model", "cwe-581"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "kt" if endswith(path, ".kt")

_decl := {
	"java": {
		"equals": `^\s*(?:@\w+\s+)*public\s+(?:final\s+)?boolean\s+equals\s*\(\s*(?:final\s+)?(?:@\w+\s+)?(?:java\.lang\.)?Object\s+\w+\s*\)`,
		"hashCode": `^\s*(?:@\w+\s+)*public\s+(?:final\s+)?int\s+hashCode\s*\(\s*\)`,
	},
	"kt": {
		"equals": `^\s*(?:(?:public|final|open)\s+)*override\s+(?:(?:final|open)\s+)*fun\s+equals\s*\(\s*\w+\s*:\s*Any\?\s*\)`,
		"hashCode": `^\s*(?:(?:public|final|open)\s+)*override\s+(?:(?:final|open)\s+)*fun\s+hashCode\s*\(\s*\)`,
	},
}

_partner := {"equals": "hashCode", "hashCode": "equals"}

_message := {
	"equals": "equals() is overridden without hashCode(): equal objects can hash differently, so hash-based collections miss or duplicate them. Override hashCode() over the same fields",
	"hashCode": "hashCode() is overridden without equals(): objects with the same hash are still compared by identity, so hash-based collections treat equal values as distinct. Override equals() over the same fields",
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Index of the nearest type declaration above line i with a smaller indent.
_owner(lines, i) := max(cands) if {
	ind := _indent(lines[i])
	cands := [k |
		some k in numbers.range(0, i - 1)
		_indent(lines[k]) < ind
		regex.match(`\b(?:class|record|enum|interface|object)\s+\w+`, lines[k])
		not helpers.is_comment_line(lines[k])
	]
	count(cands) > 0
}

_owner(lines, i) := -1 if {
	not _has_owner(lines, i)
}

_is_decl(lines, i, lang, kind) if regex.match(_decl[lang][kind], lines[i])

# The parameter list broken after the opening parenthesis:
#   public boolean equals(
#           final Object other)
_open_decl := {
	"java": {
		"equals": `^\s*(?:@\w+\s+)*public\s+(?:final\s+)?boolean\s+equals\s*\(\s*$`,
		"hashCode": `^\s*(?:@\w+\s+)*public\s+(?:final\s+)?int\s+hashCode\s*\(\s*$`,
	},
	"kt": {
		"equals": `^\s*(?:(?:public|final|open)\s+)*override\s+(?:(?:final|open)\s+)*fun\s+equals\s*\(\s*$`,
		"hashCode": `^\s*(?:(?:public|final|open)\s+)*override\s+(?:(?:final|open)\s+)*fun\s+hashCode\s*\(\s*$`,
	},
}

_param_rest := {
	"java": {
		"equals": `^\s*(?:final\s+)?(?:@\w+\s+)?(?:java\.lang\.)?Object\s+\w+\s*\)`,
		"hashCode": `^\s*\)`,
	},
	"kt": {
		"equals": `^\s*\w+\s*:\s*Any\?\s*,?\s*\)`,
		"hashCode": `^\s*\)`,
	},
}

_is_decl(lines, i, lang, kind) if {
	regex.match(_open_decl[lang][kind], lines[i])
	i + 1 < count(lines)
	regex.match(_param_rest[lang][kind], lines[i + 1])
}

_has_owner(lines, i) if {
	ind := _indent(lines[i])
	some k in numbers.range(0, i - 1)
	_indent(lines[k]) < ind
	regex.match(`\b(?:class|record|enum|interface|object)\s+\w+`, lines[k])
	not helpers.is_comment_line(lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	some kind in {"equals", "hashCode"}
	contains(content, kind)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, kind)
	_is_decl(lines, i, lang, kind)
	other := _partner[kind]
	not _paired(lines, i, lang, other)
	not _generated_pair(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _message[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A Kotlin data class or Java record has a compiler-generated equals and
# hashCode over the same components; overriding one of them keeps the pair.
_generated_pair(lines, i) if {
	o := _owner(lines, i)
	o >= 0
	regex.match(`\bdata\s+class\b|\brecord\s+\w+\s*[(<]`, lines[o])
}

# The same class declares the partner method at the same indent.
_paired(lines, i, lang, other) if {
	o := _owner(lines, i)
	ind := _indent(lines[i])
	some j, l in lines
	j != i
	contains(l, other)
	_indent(l) == ind
	_is_decl(lines, j, lang, other)
	_owner(lines, j) == o
}
