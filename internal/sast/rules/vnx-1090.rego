# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1090

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1090",
	"name": "Method Containing Access of a Member Element from Another Class",
	"description": "Python code reaches into another class's private member through its name-mangled form: an attribute access obj._Owner__attr (read or write) or getattr/setattr/hasattr/delattr(obj, \"_Owner__attr\"), where Owner is not the class the code is written in. A double-underscore attribute is the owning class's private state; touching it from elsewhere couples the caller to that class's internals and bypasses whatever invariants (validation, locking, auditing) its own methods enforce. Reported: the line holding the access, including a subclass reaching its parent's private member (self._Base__token). Not reported: a class using its own mangled name, ordinary single-underscore (protected) attributes, dunder names (__class__, __dict__), the mangled name inside a plain string or comment, and test files (white-box tests). Access to another class's protected or public members is not judged: without types it cannot be told apart from ordinary use.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1090/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1090],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["encapsulation", "maintainability", "cwe-1090"],
}

# obj._Owner__attr: Owner is the mangling class, attr is not a dunder.
_access_re := `[A-Za-z0-9_\)\]]\s*\.\s*_([A-Za-z][A-Za-z0-9]*)__([A-Za-z][A-Za-z0-9_]*[A-Za-z0-9])\b`

_reflect_re := `\b(?:getattr|setattr|hasattr|delattr)\s*\(\s*[^,]+,\s*['"]_([A-Za-z][A-Za-z0-9]*)__([A-Za-z][A-Za-z0-9_]*[A-Za-z0-9])['"]`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Remove string literals so a mangled name quoted in a message is not an access.
_strip_strings(line) := regex.replace(line, `'[^']*'|"[^"]*"`, `""`)

_owners(line) := {o |
	some m in regex.find_all_string_submatch_n(_access_re, _strip_strings(line), -1)
	not endswith(m[2], "_")
	o := m[1]
} | {o |
	some m in regex.find_all_string_submatch_n(_reflect_re, line, -1)
	not endswith(m[2], "_")
	o := m[1]
}

# The class whose body line i sits in: the nearest class header above it with
# a smaller indent.
_enclosing_class(lines, classes, i) := name if {
	cands := [k | some k in classes; k < i; _indent(lines[k]) < _indent(lines[i])]
	count(cands) > 0
	k := max(cands)
	m := regex.find_all_string_submatch_n(`^\s*class\s+_*([A-Za-z0-9_]+)`, lines[k], 1)
	name := m[0][1]
}

_own_class(lines, classes, i, owner) if _enclosing_class(lines, classes, i) == owner

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`__[A-Za-z]`, content)
	regex.match(`(?m)(\._[A-Za-z][A-Za-z0-9]*__[A-Za-z]|attr\s*\()`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	classes := [k | some k, l in lines; regex.match(`^\s*class\s+\w`, l)]
	some i, line in lines
	contains(line, "__")
	not helpers.is_comment_line(line)
	some owner in _owners(line)
	not _own_class(lines, classes, i, owner)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Access to private member of class %s through its name-mangled form; call a method of %s instead of reaching into its internals", [owner, owner]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
