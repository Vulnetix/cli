# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1079

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1079",
	"name": "Parent Class without Virtual Destructor Method",
	"description": "A C++ class or struct with no base clause that declares at least one virtual member function (so it is meant to be used through a base pointer; the virtual may follow attributes such as [[nodiscard]]) but whose destructor is not virtual and is public: no destructor declared at all, or ~Name() declared without virtual in a public section. Deleting a derived object through a pointer to this base (delete base; or a std::unique_ptr<Base>) is undefined behaviour and in practice skips the derived destructor, leaking or corrupting what it owns. The finding is on the class header. A class head that VNX-1087 (Class with Virtual Method without a Virtual Destructor) reports is the same defect and is reported by VNX-1087, so it appears once; this rule keeps the classes VNX-1087 does not judge: a public non-virtual destructor in a class that also has a protected or private section, and .ipp, .tpp, .inl, .h++ and .c++ files. Not reported: a virtual destructor (virtual ~Name(), = default or a body, also with virtual alone on the line above), a protected or private destructor (the idiom for bases that must not be deleted polymorphically), classes with no virtual members, final classes, derived classes (a base's virtual destructor makes theirs virtual too), forward declarations, test sources, and text in comments. The class body ends at the first }; at the header's indentation; a nested class's virtual members are told apart by their deeper indentation, and multi-line base clauses are not parsed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1079/",
	"languages": ["cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1079],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["parent-class-without-virtual-destructor", "cwe-1079"],
}

_exts := [".h", ".hh", ".hpp", ".hxx", ".h++", ".cpp", ".cc", ".cxx", ".c++", ".ipp", ".tpp", ".inl"]

_cpp_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

# A class header with no base clause and no `final`: the line ends after the
# name or opens the body. An optional template prefix and an upper-case
# export macro are allowed.
_header_re := `^([ \t]*)(?:template\s*<[^>]*>\s*)?(class|struct)\s+(?:[A-Z_][A-Z0-9_]*(?:\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*(\{.*)?$`

_body_end(lines, i, indent) := e if {
	end_re := concat("", ["^", indent, `\}\s*;`])
	ends := [k | some k in numbers.range(i + 1, min([i + 400, count(lines) - 1])); regex.match(end_re, lines[k])]
	e := ends[0]
}

_opens_body(lines, i, m) if m[4] != ""

_opens_body(lines, i, m) if {
	m[4] == ""
	i + 1 < count(lines)
	startswith(trim_space(lines[i + 1]), "{")
}

# `virtual` may follow C++ attributes ([[nodiscard]] virtual ...). A `virtual`
# alone on its line followed by the destructor is the destructor.
_virtual_re := `^\s*(?:\[\[[^\]]*\]\]\s*)*virtual\b`

_virtual_member(lines, v) if {
	regex.match(_virtual_re, lines[v])
	not regex.match(`^\s*virtual\s+~`, lines[v])
	not _lone_virtual_dtor(lines, v)
}

_lone_virtual_dtor(lines, v) if {
	regex.match(`^\s*virtual\s*$`, lines[v])
	v + 1 < count(lines)
	regex.match(`^\s*~`, lines[v + 1])
}

# A virtual member of this class itself: at the class's member indentation
# (the shallowest member line), so a nested class's virtual does not count.
_has_virtual_member(lines, i, e) if {
	virtuals := [v | some v in numbers.range(i + 1, e - 1); _virtual_member(lines, v)]
	count(virtuals) > 0
	indents := [_indent(lines[k]) |
		some k in numbers.range(i + 1, e - 1)
		_member_line(lines[k])
	]
	base := min(indents)
	some v in virtuals
	_indent(lines[v]) == base
}

_indent(line) := count(regex.find_all_string_submatch_n(`^[ \t]*`, line, 1)[0][0])

_member_line(line) if {
	t := trim_space(line)
	t != ""
	not regex.match(`^(#|//|/\*|\*|\{|\}|(public|protected|private)\s*:)`, t)
}

_dtor_re(name) := concat("", [`^\s*(?:(?:inline|explicit|constexpr|virtual)\s+)*~\s*`, name, `\s*\(`])

_access_at(lines, i, j, kind) := a if {
	specs := [regex.find_all_string_submatch_n(`^\s*(public|protected|private)\s*:`, lines[k], 1)[0][1] |
		some k in numbers.range(i + 1, j - 1)
		regex.match(`^\s*(public|protected|private)\s*:`, lines[k])
	]
	count(specs) > 0
	a := specs[count(specs) - 1]
} else := "public" if {
	kind == "struct"
} else := "private"

# The destructor is either absent (implicitly public and non-virtual) or
# declared non-virtual in a public section.
_bad_dtor(lines, i, e, name, kind) if {
	dre := _dtor_re(name)
	not _any_dtor(lines, i, e, dre)
}

_bad_dtor(lines, i, e, name, kind) if {
	dre := _dtor_re(name)
	some j in numbers.range(i + 1, e - 1)
	regex.match(dre, lines[j])
	not regex.match(`\bvirtual\b`, lines[j])
	_access_at(lines, i, j, kind) == "public"
}

_any_dtor(lines, i, e, dre) if {
	some j in numbers.range(i + 1, e - 1)
	regex.match(dre, lines[j])
}

_virtual_dtor(lines, i, e, name) if {
	some j in numbers.range(i + 1, e - 1)
	regex.match(concat("", [`^\s*virtual\s+~\s*`, name, `\s*\(`]), lines[j])
}

_virtual_dtor(lines, i, e, name) if {
	some j in numbers.range(i + 1, e - 2)
	_lone_virtual_dtor(lines, j)
	regex.match(concat("", [`^\s*~\s*`, name, `\s*\(`]), lines[j + 1])
}

findings contains finding if {
	some path, content in input.file_contents
	_cpp_file(path)
	not helpers.is_test_path(path)
	regex.match(concat("", ["(?m)", _virtual_re]), content)
	regex.match(`(?m)^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(template|class|struct)\b`, line)
	m := regex.find_all_string_submatch_n(_header_re, line, 1)[0]
	_opens_body(lines, i, m)
	e := _body_end(lines, i, m[1])
	_has_virtual_member(lines, i, e)
	not _virtual_dtor(lines, i, e, m[3])
	_bad_dtor(lines, i, e, m[3], m[2])
	not _reported_by_1087(path, content, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s has virtual members but no public virtual destructor; declare virtual ~%s() (or make the destructor protected)", [m[3], m[3]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Classes VNX-1087 reports ──────────────────────────────────────────────
# A class with virtual members and no virtual destructor is one defect, and
# VNX-1087 (Class with Virtual Method without a Virtual Destructor) reports
# it at the same class head. The conditions below are VNX-1087's own findings
# conditions, copied with an _r87_ prefix, so this rule stays quiet only on a
# class head that rule does report, and keeps the ones it does not: a public
# non-virtual destructor in a class that also has a protected or private
# section, and the extra file extensions (.ipp, .tpp, .inl, .h++, .c++).
# It is evaluated only for a class this rule would otherwise report.

_reported_by_1087(path, content, lines, i, line) if {
	_r87_is_cpp(path)
	contains(content, "virtual")
	name := _r87_class_open(line)
	starts := [k | some k, l in lines; contains(l, "/*")]
	ends := [k | some k, l in lines; contains(l, "*/")]
	not _r87_in_block(starts, ends, i)
	e := _r87_class_end(lines, i)
	body := _r87_body(lines, i, e)
	_r87_has_virtual_method(body, name)
	not _r87_has_virtual_dtor(body, name)
	not _r87_dtor_protected(body, name)
	not _r87_derived_override(lines, i, body)
	not _r87_derived_unknown(content, lines, i)
}

# How far past a class declaration to look for its closing brace. A class longer
# than this is not analysed rather than guessed at.
_r87_max_class_lines := 400

_r87_is_cpp(path) if regex.match(`\.(cpp|cc|cxx|hpp|hh|hxx|h)$`, path)

# A .h may be C or C++. `class`/`struct` with virtual members only parses as
# C++, so including .h costs nothing on C sources.

_r87_is_comment_line(line) if startswith(trim_space(line), "//")

_r87_is_comment_line(line) if startswith(trim_space(line), "*")

_r87_is_comment_line(line) if startswith(trim_space(line), "/*")

# The line without its // and /* */ comments.
_r87_code(line) := regex.replace(regex.replace(line, `/\*.*?\*/`, ""), `//.*$`, "")

_r87_indent(line) := count(line) - count(trim_left(line, " \t"))

# The opening line of a class or struct definition, capturing the name.
#
# Excluded deliberately:
#   - `class X;`      a forward declaration, no body to analyse
#   - `class X final` cannot be derived from, so it can never be deleted through
#                     a base pointer of its own type
_r87_class_open(line) := name if {
	not _r87_is_comment_line(line)
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
_r87_class_end(lines, i) := e if {
	limit := min([count(lines) - 1, i + _r87_max_class_lines])
	limit > i
	ends := [k |
		some k in numbers.range(i + 1, limit)
		regex.match(`^\s*\}\s*;`, lines[k])
	]
	count(ends) > 0
	ind := _r87_indent(lines[i])
	same := [k | some k in ends; _r87_indent(lines[k]) == ind]
	e := _r87_first_or(same, ends[0])
}

_r87_first_or(xs, d) := xs[0] if count(xs) > 0

_r87_first_or(xs, d) := d if count(xs) == 0

# Code of the body lines after the class head, comments removed.
_r87_body(lines, i, e) := [_r87_code(lines[k]) | some k in numbers.range(i + 1, e)]

# `virtual` naming a base class (`: virtual public Base`), not a member.
_r87_virtual_base(line) if regex.match(`\bvirtual\s+(?:public|protected|private)\b|\b(?:public|protected|private)\s+virtual\b`, line)

# A `virtual` on its own line, completed by a destructor on the next one.
_r87_split_virtual_dtor(body, k, name) if {
	regex.match(`^\s*virtual\s*$`, body[k])
	regex.match(sprintf(`^\s*~\s*%s\s*\(`, [name]), body[k + 1])
}

# The indentation of the class's own members: the least-indented code line of
# the body other than an access label or a lone brace. Members of a nested
# class or struct sit deeper and are not this class's.
_r87_member_indent(body) := min(xs) if {
	xs := [_r87_indent(l) |
		some l in body
		trim_space(l) != ""
		not _r87_is_comment_line(l)
		not regex.match(`^\s*(?:public|protected|private)\s*:|^\s*[{}]`, l)
	]
	count(xs) > 0
}

# At least one virtual member function that is not itself the destructor.
_r87_has_virtual_method(body, name) if {
	mi := _r87_member_indent(body)
	some k, line in body
	regex.match(`\bvirtual\b`, line)
	_r87_indent(line) == mi
	not _r87_is_comment_line(line)
	not regex.match(`\bvirtual\b[^;{]*~`, line)
	not _r87_virtual_base(line)
	not _r87_split_virtual_dtor(body, k, name)
}

# A destructor declared virtual, or marked override/final — both of which imply
# virtual because only a virtual function can override one.
_r87_has_virtual_dtor(body, name) if {
	some line in body
	regex.match(sprintf(`\bvirtual\b[^;{]*~\s*%s\s*\(`, [name]), line)
}

_r87_has_virtual_dtor(body, name) if {
	some k, _ in body
	_r87_split_virtual_dtor(body, k, name)
}

_r87_has_virtual_dtor(body, name) if {
	some line in body
	regex.match(sprintf(`~\s*%s\s*\([^)]*\)[^;{]*\b(override|final)\b`, [name]), line)
}

# A derived class whose members say `override`/`final` inherits from a
# polymorphic base: the base's destructor decides, and a virtual one makes this
# one virtual too without the keyword. The base is checked where it is defined.
_r87_derived_override(lines, i, body) if {
	count(_r87_bases(lines, i)) > 0
	some line in body
	regex.match(`\)[^;{]*\b(?:override|final)\b`, line)
}

# Base class names from the class head (`class D : public a::B<T>, C {`), last
# `::` component, template arguments removed.
_r87_bases(lines, i) := {b |
	head := concat(" ", [_r87_code(lines[i]), _r87_code(lines[min([i + 1, count(lines) - 1])])])
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
_r87_derived_unknown(content, lines, i) if {
	bs := _r87_bases(lines, i)
	count(bs) > 0
	count([b | some b in bs; _r87_defined_here(content, b)]) == 0
}

_r87_derived_unknown(content, lines, i) if {
	some b in _r87_bases(lines, i)
	regex.match(sprintf(`\bvirtual\b[^;{]*~\s*%s\s*\(|~\s*%s\s*\([^)]*\)[^;{]*\b(?:override|final)\b`, [b, b]), content)
}

# The base is defined in this file as a root class (no base clause of its own),
# so whether its destructor is virtual can be read here.
_r87_defined_here(content, b) if regex.match(sprintf(`(?m)^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+(?:[A-Z_][A-Z0-9_]*\s+)?%s\s*(?:\{[^;]*)?$`, [b]), content)

# Line k lies inside a /* */ comment opened on an earlier line and not yet closed.
_r87_in_block(starts, ends, k) if {
	some s in starts
	s < k
	count([e | some e in ends; e >= s; e < k]) == 0
}

# A non-virtual destructor that cannot be reached through a base pointer is the
# other sanctioned resolution, so it must not be reported. Recognising the
# access label anywhere in the class is deliberately conservative: it can miss a
# real defect, but it will not tell someone who already applied the documented
# alternative that they were wrong.
_r87_dtor_protected(body, name) if {
	some line in body
	regex.match(`^\s*(protected|private)\s*:`, line)
	some other in body
	regex.match(sprintf(`~\s*%s\s*\(`, [name]), other)
}

