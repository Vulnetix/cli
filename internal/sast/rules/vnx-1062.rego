# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1062

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1062",
	"name": "Parent Class with References to Child Class",
	"description": "Java: a class refers to one of its own subclasses. The rule collects every `class Child extends Parent` (or `extends pkg.Parent`) declaration in the scanned Java files, then reports a line of Parent's own source file (Parent.java) that tests `instanceof Child`, matches `case Child c ->` in a pattern switch, compares `getClass() == Child.class`, casts to `(Child)`, or constructs `new Child(` for a subclass declared in a different file. The parent then depends on its children, so adding or changing a subclass forces a change to the base class, and type switches in the parent bypass polymorphism. Not reported: `Child.class` registrations that are not type tests (Jackson @JsonSubTypes and similar annotations), references to the parent's own type, unrelated classes with similar names, a sealed class's `permits` clause, subclasses nested in the parent's own file, and comments or string literals. Subclasses declared outside the scanned files are not known.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1062/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1062],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["parent-class-ref-to-child", "inheritance", "maintainability", "java", "cwe-1062"],
}

_ext_re := `\bclass\s+([A-Z]\w*)(?:\s*<[^{;]*?>)?\s+extends\s+(?:[a-z_]\w*\.)*([A-Z]\w*)`

# [child, parent, file] for every subclass declaration.
_pairs contains [m[1], m[2], path] if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "extends")
	some m in regex.find_all_string_submatch_n(_ext_re, content, -1)
	m[1] != m[2]
}

_base(path) := b if {
	parts := split(path, "/")
	b := trim_suffix(parts[count(parts) - 1], ".java")
}

# Java files keyed by their simple file name (the top-level class).
_java_by_base[_base(path)] contains path if {
	some path, _ in input.file_contents
	endswith(path, ".java")
}

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

findings contains finding if {
	some pair in _pairs
	child := pair[0]
	parent := pair[1]
	some path in _java_by_base[parent]
	path != pair[2]
	content := input.file_contents[path]
	contains(content, child)
	ref_re := concat("", [
		`(?:\binstanceof\s+`, child, `\b|\(\s*`, child, `\s*\)\s*[\w(]|\bnew\s+`, child, `\s*(?:<[^>]*>)?\s*\(`,
		`|\bcase\s+`, child, `\s+[a-z_]\w*\s*(?:->|:|when\b)`,
		`|(?:==|!=)\s*`, child, `\.class\b|\b`, child, `\.class\s*(?:==|!=|\.isInstance\s*\(|\.equals\s*\(\s*getClass)`,
		`)`,
	])
	lines := split(content, "\n")
	some i, line in lines
	contains(line, child)
	not helpers.is_comment_line(line)
	not contains(line, "permits")
	regex.match(ref_re, _strip_strings(line))
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Base class %s refers to its subclass %s (instanceof, cast or construction): the parent depends on its children; move the behaviour into an overridden method", [parent, child]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
