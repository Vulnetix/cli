# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1066

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1066",
	"name": "Missing Serialization Control Element",
	"description": "Java: a class that declares `implements Serializable` (or `java.io.Serializable`, anywhere in its implements list, with the header split across lines) but declares no `serialVersionUID` field among its own members. Without it the stream identifier is computed from the class shape, so any recompilation or harmless change breaks deserialization of stored data, and the class has no explicit control over its serialized form. Nested classes are judged on their own members: an outer class's serialVersionUID does not cover a nested Serializable class. Not reported: interfaces, enums and records (whose serialization ignores the field), Externalizable classes, classes that only inherit Serializable through `extends` (the supertype is not resolved), lookalike names such as SerializableHelper, and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1066/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1066],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-serialization-control", "serialization", "java", "cwe-1066"],
}

_class_re := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp)\s+)*class\s+[A-Z][\w$]*`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

# Index of the line holding the class body's opening brace (within 6 lines).
_open(lines, i) := min([m |
	some m in numbers.range(i, min([count(lines) - 1, i + 5]))
	contains(_strip(lines[m]), "{")
])

_header(lines, i, h) := concat(" ", [_strip(l) | some l in array.slice(lines, i, h + 1)])

# Index of the brace that closes the class: the first `}` line at or left of
# the header's indentation.
_close(lines, i, h) := min(ends) if {
	ii := _indent(lines[i])
	ends := [m |
		some m in numbers.range(h + 1, min([count(lines) - 1, h + 3000]))
		startswith(trim_space(lines[m]), "}")
		_indent(lines[m]) <= ii
	]
	count(ends) > 0
}

# Indentation of the class's own members.
_member_indent(lines, h, e) := _indent(lines[m]) if {
	m := min([k | some k in numbers.range(h + 1, e - 1); trim_space(lines[k]) != ""])
}

_has_uid(lines, h, e) if {
	mi := _member_indent(lines, h, e)
	some k in numbers.range(h + 1, e - 1)
	contains(lines[k], "serialVersionUID")
	_indent(lines[k]) == mi
	regex.match(`\bstatic\b.*\bserialVersionUID\s*=`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "Serializable")
	regex.match(`\bimplements\b[^{;]*\bSerializable\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "class")
	not helpers.is_comment_line(line)
	regex.match(_class_re, _strip(line))
	h := _open(lines, i)
	head := _header(lines, i, h)
	regex.match(`\bimplements\b[^{]*(?:^|[\s,.])Serializable\s*(?:,|\{|$)`, trim_space(split(head, "{")[0]))
	e := _close(lines, i, h)
	not _has_uid(lines, h, e)
	finding := {
		"rule_id": metadata.id,
		"message": "Serializable class declares no serialVersionUID: its stream identifier changes with every recompilation; add `private static final long serialVersionUID = 1L;`",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
