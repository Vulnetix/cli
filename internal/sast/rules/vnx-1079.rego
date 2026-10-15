# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1079

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1079",
	"name": "Parent Class without Virtual Destructor Method",
	"description": "A C++ class or struct with no base clause that declares at least one virtual member function (so it is meant to be used through a base pointer; the virtual may follow attributes such as [[nodiscard]]) but whose destructor is not virtual and is public: no destructor declared at all, or ~Name() declared without virtual in a public section. Deleting a derived object through a pointer to this base (delete base; or a std::unique_ptr<Base>) is undefined behaviour and in practice skips the derived destructor, leaking or corrupting what it owns. The finding is on the class header. Not reported: a virtual destructor (virtual ~Name(), = default or a body, also with virtual alone on the line above), a protected or private destructor (the idiom for bases that must not be deleted polymorphically), classes with no virtual members, final classes, derived classes (a base's virtual destructor makes theirs virtual too), forward declarations, test sources, and text in comments. The class body ends at the first }; at the header's indentation; a nested class's virtual members are told apart by their deeper indentation, and multi-line base clauses are not parsed.",
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
