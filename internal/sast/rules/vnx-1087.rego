# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1087

import rego.v1

# CWE-1087 is a C++ object-lifetime defect: a class that declares virtual
# methods but not a virtual destructor. Deleting such an object through a
# base-class pointer runs the base destructor only, so the derived class's
# destructor never runs and whatever it owned is leaked or left in an
# inconsistent state. The standard is explicit that this is undefined behaviour.
#
# This rule previously shipped as "function has no docstring" against Python —
# nothing to do with its declared CWE, byte-identical to VNX-1117, and the
# single largest source of findings on any Python repo. VNX-1117 keeps the
# general documentation lint; this rule now checks what its id says it checks.
metadata := {
	"id": "VNX-1087",
	"name": "Class with Virtual Method without a Virtual Destructor",
	"description": "A C++ class declares at least one virtual method but no virtual destructor. Deleting an instance through a base-class pointer will not run the derived destructor, leaking whatever it owns. Declare the destructor virtual, or make it protected and non-virtual to forbid deletion through the base.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1087/",
	"languages": ["cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1087],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cwe-1087", "object-lifetime", "cpp"],
}

# How far past a class declaration to look for its closing brace. A class longer
# than this is not analysed rather than guessed at.
_max_class_lines := 400

_is_cpp(path) if endswith(path, ".cpp")

_is_cpp(path) if endswith(path, ".cc")

_is_cpp(path) if endswith(path, ".cxx")

_is_cpp(path) if endswith(path, ".hpp")

_is_cpp(path) if endswith(path, ".hh")

_is_cpp(path) if endswith(path, ".hxx")

# A .h may be C or C++. `class` with a body only parses as C++, and the rule
# requires that anyway, so including .h costs nothing on C sources.
_is_cpp(path) if endswith(path, ".h")

_is_comment_line(line) if startswith(trim_space(line), "//")

_is_comment_line(line) if startswith(trim_space(line), "*")

_is_comment_line(line) if startswith(trim_space(line), "/*")

# The opening line of a class definition, capturing the name.
#
# Excluded deliberately:
#   - `class X;`      a forward declaration, no body to analyse
#   - `class X final` cannot be derived from, so it can never be deleted through
#                     a base pointer of its own type
_class_open(line) := name if {
	not _is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:template\s*<[^>]*>\s*)?class\s+(?:[A-Z_][A-Z0-9_]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\b`, line, 1)
	count(m) == 1
	name := m[0][1]
	not regex.match(`;\s*(//.*)?$`, line)
	not regex.match(`\bfinal\b`, line)
}

# The closing `};` of the class body, bounded so an unterminated or very large
# class is skipped rather than mis-attributed to the next one.
_class_end(lines, i) := e if {
	limit := min([count(lines) - 1, i + _max_class_lines])
	limit > i
	ends := [k |
		some k in numbers.range(i + 1, limit)
		regex.match(`^\s*\}\s*;`, lines[k])
	]
	count(ends) > 0
	e := ends[0]
}

_body(lines, i, e) := [lines[k] | some k in numbers.range(i, e)]

# At least one virtual member function that is not itself the destructor.
_has_virtual_method(body) if {
	some line in body
	not _is_comment_line(line)
	regex.match(`\bvirtual\b`, line)
	not regex.match(`\bvirtual\b[^;{]*~`, line)
}

# A destructor declared virtual, or marked override/final — both of which imply
# virtual because only a virtual function can override one.
_has_virtual_dtor(body, name) if {
	some line in body
	not _is_comment_line(line)
	regex.match(sprintf(`\bvirtual\b[^;{]*~\s*%s\s*\(`, [name]), line)
}

_has_virtual_dtor(body, name) if {
	some line in body
	not _is_comment_line(line)
	regex.match(sprintf(`~\s*%s\s*\([^)]*\)[^;{]*\b(override|final)\b`, [name]), line)
}

# A non-virtual destructor that cannot be reached through a base pointer is the
# other sanctioned resolution, so it must not be reported. Recognising the
# access label anywhere in the class is deliberately conservative: it can miss a
# real defect, but it will not tell someone who already applied the documented
# alternative that they were wrong.
_dtor_protected(body, name) if {
	some line in body
	regex.match(`^\s*(protected|private)\s*:`, line)
	some other in body
	regex.match(sprintf(`~\s*%s\s*\(`, [name]), other)
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cpp(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	name := _class_open(line)
	e := _class_end(lines, i)
	body := _body(lines, i, e)
	_has_virtual_method(body)
	not _has_virtual_dtor(body, name)
	not _dtor_protected(body, name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("class %s declares virtual methods but no virtual destructor; deleting it through a base pointer will not run its destructor", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
