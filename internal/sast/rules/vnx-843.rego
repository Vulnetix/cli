# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_843

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-843",
	"name": "Access of Resource Using Incompatible Type ('Type Confusion')",
	"description": "An object is read through a type it may not have. Reported in C and C++: (1) a generic socket address (struct sockaddr *, struct sockaddr_storage) cast to a family-specific one (struct sockaddr_in, sockaddr_in6, sockaddr_un, sockaddr_ll, sockaddr_nl), by a C cast or reinterpret_cast, when nothing in the 20 lines above within the same function, or on the line, establishes the family (sa_family/ss_family/ai_family, an AF_* constant such as the socket() call that created it) (an AF_* constant passed as an argument, as in inet_ntop(AF_INET, ...), claims a family and checks nothing) and the cast is not the start of filling the structure (its *_family assigned within the next 4 lines); an IPv6 peer read as sockaddr_in reads past the 16-byte address it was given; (2) a C++ downcast by static_cast<Derived *>/<Derived &>, std::static_pointer_cast<Derived>(p) or a C-style (Derived *) cast of a variable whose declared type (a pointer, reference, shared_ptr or unique_ptr), in the 40 lines above, is a base class of Derived according to the class declarations in the project (one or two levels of inheritance), when no condition in the 8 lines above (if/switch/case/assert/CHECK naming the variable) or a dynamic_cast/typeid tested its dynamic type, and no if/switch on a type, kind or tag field in those lines dispatches on it; a static_cast to the wrong derived class is undefined behaviour and the classic type-confusion exploit primitive. Not reported: upcasts, casts from void * (the type is not known to the rule), CRTP static_cast<Impl *>(this), numeric static_casts, reinterpret_cast to byte pointers, checked downcasts, unions and tagged-variant misuse (not decidable line by line), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-843/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [843],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["type-confusion", "cwe-843", "downcast", "sockaddr"],
}

_is_c_family(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx"}
	endswith(path, ext)
}

_is_cpp(path) if {
	some ext in {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h"}
	endswith(path, ext)
}

# String literals are blanked so a message naming a cast is not a cast.
_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# ── (1) Socket address read as the wrong family ──────────────────────────

_sa_cast := `\(\s*(?:const\s+)?(?:struct\s+)?sockaddr_(?:in6?|un|ll|nl)\s*\*\s*\)\s*[&\w(]|reinterpret_cast\s*<\s*(?:const\s+)?(?:struct\s+)?sockaddr_(?:in6?|un|ll|nl)\s*\*\s*>`

# What establishes the family: reading a *_family field, comparing or
# switching on an AF_/PF_ constant, or the socket() call that chose it. An
# AF_* constant passed as an argument (inet_ntop(AF_INET, ...)) only claims a
# family, it does not check one.
_family_known := `\b(?:sa_family|ss_family|ai_family|sin_family|sin6_family|sun_family|sll_family|nl_family)\b|(?:==|!=)\s*[AP]F_\w+|\b[AP]F_\w+\s*(?:==|!=)|\bcase\s+[AP]F_|\bsocket\s*\(\s*[AP]F_`

_family_checked(lines, i) if {
	some j in numbers.range(max([0, i - 20]), i)
	not helpers.is_comment_line(lines[j])
	regex.match(_family_known, lines[j])
	not _function_ends_between(lines, j, i)
}

# A column-0 closing brace between j and i: the check belongs to an earlier
# function.
_function_ends_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	startswith(lines[k], "}")
}

# The cast starts filling the structure: its family is assigned just after.
_family_checked(lines, i) if {
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	regex.match(`_family\s*=[^=]`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c_family(path)
	contains(content, "sockaddr_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "sockaddr_")
	not helpers.is_comment_line(line)
	regex.match(_sa_cast, _code(line))
	not _family_checked(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A generic socket address is cast to a family-specific structure without checking its address family, so an address of another family (IPv6 read as sockaddr_in, a Unix socket path read as an IP address) is read through the wrong type. Check sa_family/ss_family before the cast and handle each family separately",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (2) Unchecked C++ downcast ───────────────────────────────────────────

# [derived, base] pairs declared anywhere in the project's C++ sources.
_direct_bases contains [d, b] if {
	some path, content in input.file_contents
	_is_cpp(path)
	contains(content, ":")
	some m in regex.find_all_string_submatch_n(`(?:class|struct)\s+(?:[A-Z][A-Z0-9_]*\s+)?(\w+)\s*(?:final\s*)?:\s*([^{;()]+?)\s*\{`, content, -1)
	d := m[1]
	some part in split(m[2], ",")
	b := _base_name(part)
	b != ""
	b != d
}

_base_name(part) := b if {
	p := regex.replace(part, `<[^>]*>`, "")
	words := [w | some w in regex.find_all_string_submatch_n(`\w+`, p, -1); not _access[w[0]]]
	count(words) > 0
	b := words[count(words) - 1][0]
}

_access := {"public", "protected", "private", "virtual"}

_bases := _direct_bases | {[d, b] |
	some [d, x] in _direct_bases
	some [x2, b] in _direct_bases
	x2 == x
	b != d
}

_derived := {d | some [d, _] in _bases}

_static_down := `static_cast\s*<\s*(?:const\s+)?(?:\w+::)*(\w+)\s*(?:const\s*)?[*&]\s*>\s*\(\s*\*?\s*(\w+)\s*\)`

_cstyle_down := `\(\s*(?:const\s+)?(\w+)\s*\*\s*\)\s*\(?\s*(\w+)\b`

# Each (target, operand) cast on the line; a static_cast whose operand is on
# the next line is joined first.
_casts(lines, i, c) := {[m[1], m[2]] |
	contains(c, "static_cast")
	joined := concat(" ", [c, _next(lines, i)])
	some m in regex.find_all_string_submatch_n(_static_down, joined, -1)
} | {[m[1], m[2]] |
	contains(c, "static_pointer_cast")
	some m in regex.find_all_string_submatch_n(`static_pointer_cast\s*<\s*(?:const\s+)?(?:\w+::)*(\w+)\s*>\s*\(\s*(\w+)\s*\)`, c, -1)
} | {[m[1], m[2]] |
	contains(c, "*")
	some m in regex.find_all_string_submatch_n(_cstyle_down, c, -1)
}

_cast_line(line) if contains(line, "static_cast")

_cast_line(line) if contains(line, "pointer_cast")

_cast_line(line) if contains(line, "*)")

_cast_line(line) if contains(line, "* )")

_next(lines, i) := lines[i + 1] if i + 1 < count(lines)

_next(lines, i) := "" if i + 1 >= count(lines)

# The operand's declared type in the 40 lines above (or on the line).
_declared_type(lines, i, op) := t if {
	re := concat("", [`(?:\b(\w+)\s*(?:const\s*)?[*&]+|\b(?:shared_ptr|unique_ptr)\s*<\s*(?:const\s+)?(?:\w+::)*(\w+)\s*>\s*(?:const\s*)?&?)\s*(?:const\s+)?`, op, `\s*[,)=;\[{]`])
	decls := [t0 |
		some j in numbers.range(max([0, i - 40]), i)
		contains(lines[j], op)
		some m in regex.find_all_string_submatch_n(re, lines[j], -1)
		t0 := concat("", [m[1], m[2]])
		t0 != ""
	]
	count(decls) > 0
	t := decls[count(decls) - 1]
}

# The dynamic type was tested: a condition naming the operand, or a
# dynamic_cast/typeid, in the 8 lines above or on the line.
_checked(lines, i, op) if {
	some j in numbers.range(max([0, i - 8]), i)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(`\b(?:if|switch|case|while|assert|DCHECK\w*|CHECK\w*)\b|\?`, l)
	regex.match(concat("", [`\b`, op, `\b`]), l)
}

# A tagged dispatch: a condition on a type/kind/tag field just above
# (if (m_leaf_type == Small) static_cast<const ArrayString&>(*m_leaf)).
_checked(lines, i, _) if {
	some j in numbers.range(max([0, i - 8]), i)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(`\b(?:if|switch|case)\b`, l)
	regex.match(`(?i)(?:type|kind|tag)\w*(?:\(\s*\))?\s*(?:==|!=)|(?:==|!=)\s*[\w:]*(?:type|kind|tag)|switch\s*\([^)]*(?:type|kind|tag)|\bcase\s+[\w:]*(?:type|kind|tag)`, l)
}

_checked(lines, i, _) if {
	some j in numbers.range(max([0, i - 8]), i)
	regex.match(`\bdynamic_cast\s*<|\btypeid\s*\(`, lines[j])
	not helpers.is_comment_line(lines[j])
}

findings contains finding if {
	count(_derived) > 0
	some path, content in input.file_contents
	_is_cpp(path)
	lines := split(content, "\n")
	some i, line in lines
	_cast_line(line)
	not helpers.is_comment_line(line)
	c := _code(line)
	some [target, op] in _casts(lines, i, c)
	_derived[target]
	op != "this"
	t := _declared_type(lines, i, op)
	[target, t] in _bases
	not _checked(lines, i, op)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("A %s is cast down to %s without checking that it is one: if it is another subclass the code reads and writes it through the wrong layout (type confusion). Use dynamic_cast and test the result, or check the object's kind first", [t, target]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
