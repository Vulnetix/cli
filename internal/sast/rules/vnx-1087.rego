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
	"description": "A C++ class or struct declares at least one virtual member function of its own but no virtual destructor (`virtual ~T()`, possibly split over two lines, or `~T() override/final`). Deleting an instance through a base-class pointer will not run the derived destructor, leaking whatever it owns. Declare the destructor virtual, or make it protected and non-virtual to forbid deletion through the base. One finding per class, at its head. Not reported: final classes, classes with a protected or private destructor, forward declarations, virtual base classes (`: virtual public B`), virtual members of a nested class (that class is judged on its own), class heads inside comments, and derived classes whose destructor may be virtual through their base: a derived class is judged only when one of its bases is a root class defined in the same file and no base declares a virtual destructor there, and never when it marks members override or final. A class body ends at the `};` at the class's own indentation and is analysed up to 400 lines.",
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

_is_cpp(path) if regex.match(`\.(cpp|cc|cxx|hpp|hh|hxx|h)$`, path)

# A .h may be C or C++. `class`/`struct` with virtual members only parses as
# C++, so including .h costs nothing on C sources.

_is_comment_line(line) if startswith(trim_space(line), "//")

_is_comment_line(line) if startswith(trim_space(line), "*")

_is_comment_line(line) if startswith(trim_space(line), "/*")

# The line without its // and /* */ comments.
_code(line) := regex.replace(regex.replace(line, `/\*.*?\*/`, ""), `//.*$`, "")

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The opening line of a class or struct definition, capturing the name.
#
# Excluded deliberately:
#   - `class X;`      a forward declaration, no body to analyse
#   - `class X final` cannot be derived from, so it can never be deleted through
#                     a base pointer of its own type
_class_open(line) := name if {
	not _is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+(?:[A-Z_][A-Z0-9_]*\s+)?((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*[A-Za-z_][A-Za-z0-9_]*)\b`, line, 1)
	count(m) == 1
	# `struct Outer::Inner {` defines Inner, whose destructor is `~Inner`.
	parts := split(regex.replace(m[0][1], `\s+`, ""), "::")
	name := parts[count(parts) - 1]
	not regex.match(`;\s*(//.*)?$`, line)
	not regex.match(`\bfinal\b`, line)
}

# The closing `};` of the class body at the class's own indentation, so a
# nested enum, struct or lambda closing with `};` does not end it early. When
# no brace sits at that indentation, the first `};` is taken. Bounded so an
# unterminated or very large class is skipped rather than mis-attributed.
_class_end(lines, i) := e if {
	limit := min([count(lines) - 1, i + _max_class_lines])
	limit > i
	ends := [k |
		some k in numbers.range(i + 1, limit)
		regex.match(`^\s*\}\s*;`, lines[k])
	]
	count(ends) > 0
	ind := _indent(lines[i])
	same := [k | some k in ends; _indent(lines[k]) == ind]
	e := _first_or(same, ends[0])
}

_first_or(xs, d) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

# Code of the body lines after the class head, comments removed.
_body(lines, i, e) := [_code(lines[k]) | some k in numbers.range(i + 1, e)]

# `virtual` naming a base class (`: virtual public Base`), not a member.
_virtual_base(line) if regex.match(`\bvirtual\s+(?:public|protected|private)\b|\b(?:public|protected|private)\s+virtual\b`, line)

# A `virtual` on its own line, completed by a destructor on the next one.
_split_virtual_dtor(body, k, name) if {
	regex.match(`^\s*virtual\s*$`, body[k])
	regex.match(sprintf(`^\s*~\s*%s\s*\(`, [name]), body[k + 1])
}

# The indentation of the class's own members: the least-indented code line of
# the body other than an access label or a lone brace. Members of a nested
# class or struct sit deeper and are not this class's.
_member_indent(body) := min(xs) if {
	xs := [_indent(l) |
		some l in body
		trim_space(l) != ""
		not _is_comment_line(l)
		not regex.match(`^\s*(?:public|protected|private)\s*:|^\s*[{}]`, l)
	]
	count(xs) > 0
}

# At least one virtual member function that is not itself the destructor.
_has_virtual_method(body, name) if {
	mi := _member_indent(body)
	some k, line in body
	regex.match(`\bvirtual\b`, line)
	_indent(line) == mi
	not _is_comment_line(line)
	not regex.match(`\bvirtual\b[^;{]*~`, line)
	not _virtual_base(line)
	not _split_virtual_dtor(body, k, name)
}

# A destructor declared virtual, or marked override/final — both of which imply
# virtual because only a virtual function can override one.
_has_virtual_dtor(body, name) if {
	some line in body
	regex.match(sprintf(`\bvirtual\b[^;{]*~\s*%s\s*\(`, [name]), line)
}

_has_virtual_dtor(body, name) if {
	some k, _ in body
	_split_virtual_dtor(body, k, name)
}

_has_virtual_dtor(body, name) if {
	some line in body
	regex.match(sprintf(`~\s*%s\s*\([^)]*\)[^;{]*\b(override|final)\b`, [name]), line)
}

# A derived class whose members say `override`/`final` inherits from a
# polymorphic base: the base's destructor decides, and a virtual one makes this
# one virtual too without the keyword. The base is checked where it is defined.
_derived_override(lines, i, body) if {
	count(_bases(lines, i)) > 0
	some line in body
	regex.match(`\)[^;{]*\b(?:override|final)\b`, line)
}

# Base class names from the class head (`class D : public a::B<T>, C {`), last
# `::` component, template arguments removed.
_bases(lines, i) := {b |
	head := concat(" ", [_code(lines[i]), _code(lines[min([i + 1, count(lines) - 1])])])
	some m in regex.find_all_string_submatch_n(`^[^{]*?[^:]:([^:{][^{]*)`, head, 1)
	some raw in split(regex.replace(m[1], `<[^<>]*(?:<[^<>]*>[^<>]*)*>`, ""), ",")
	t := trim_space(regex.replace(raw, `\b(?:public|protected|private|virtual)\b`, ""))
	t != ""
	parts := split(regex.replace(t, `\s+`, ""), "::")
	b := parts[count(parts) - 1]
	regex.match(`^[A-Za-z_]\w*$`, b)
}

# A derived class's destructor is virtual whenever its base's is, without the
# keyword, so a derived class is only judged when that is known: one of its
# bases is defined in the same file and none of its bases declares a virtual
# destructor there. A base defined elsewhere is checked where it is defined.
_derived_unknown(content, lines, i) if {
	bs := _bases(lines, i)
	count(bs) > 0
	count([b | some b in bs; _defined_here(content, b)]) == 0
}

_derived_unknown(content, lines, i) if {
	some b in _bases(lines, i)
	regex.match(sprintf(`\bvirtual\b[^;{]*~\s*%s\s*\(|~\s*%s\s*\([^)]*\)[^;{]*\b(?:override|final)\b`, [b, b]), content)
}

# The base is defined in this file as a root class (no base clause of its own),
# so whether its destructor is virtual can be read here.
_defined_here(content, b) if regex.match(sprintf(`(?m)^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+(?:[A-Z_][A-Z0-9_]*\s+)?%s\s*(?:\{[^;]*)?$`, [b]), content)

# Line k lies inside a /* */ comment opened on an earlier line and not yet closed.
_in_block(starts, ends, k) if {
	some s in starts
	s < k
	count([e | some e in ends; e >= s; e < k]) == 0
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
	some path, content in input.file_contents
	_is_cpp(path)
	contains(content, "virtual")
	lines := split(content, "\n")
	starts := [k | some k, l in lines; contains(l, "/*")]
	ends := [k | some k, l in lines; contains(l, "*/")]
	some i, line in lines
	name := _class_open(line)
	not _in_block(starts, ends, i)
	e := _class_end(lines, i)
	body := _body(lines, i, e)
	_has_virtual_method(body, name)
	not _has_virtual_dtor(body, name)
	not _dtor_protected(body, name)
	not _derived_override(lines, i, body)
	not _derived_unknown(content, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s declares virtual methods but no virtual destructor; deleting it through a base pointer will not run its destructor", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
