# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1045

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1045",
	"name": "Parent Class with Virtual Destructor and Child Without Virtual Destructor",
	"description": "A C++ class derives from a class whose destructor is declared virtual, and declares its own destructor without virtual, override or final. C++ makes that destructor virtual anyway, so the code works, but the declaration reads as non-virtual: a reader cannot tell from the child that deleting through a base pointer is safe, and if the parent's virtual is later removed the child silently loses it (CWE-1045). Reported on the child's in-class destructor declaration (~Child(), including = default, noexcept and inline bodies) when a parent named in its base list (public, protected or private, with or without a namespace or template arguments) declares virtual ~Parent() in any C++ file of the scanned tree, including a virtual keyword on the line above. Not reported: a child destructor marked virtual, override or final; a child with no user-declared destructor (the implicit one is virtual and needs no annotation); a parent whose destructor is not virtual (a different weakness, CWE-1079 and CWE-1087, judged by VNX-1079 and VNX-1087); a parent defined outside the scanned tree; out-of-class definitions (Child::~Child()); base lists spanning lines; test code and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1045/",
	"languages": ["cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1045],
	"capec": ["CAPEC-123"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cpp", "virtual-destructor", "inheritance", "override", "cwe-1045"],
}

_cpp(path) if {
	some ext in {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".h", ".ipp", ".inl"}
	endswith(path, ext)
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(?:^|/)[^/]*_?(?:test|tests|unittest)\.(?:cpp|cc|cxx)$`, path)

_dtor_re := `^\s*(?:virtual\s+)?(?:inline\s+)?~([A-Za-z_]\w*)\s*\(`

# Classes whose destructor is declared virtual, from every C++ file.
_virtual_dtor := {m[1] |
	some path, content in input.file_contents
	_cpp(path)
	contains(content, "virtual")
	contains(content, "~")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "~")
	some m in regex.find_all_string_submatch_n(_dtor_re, line, 1)
	_virtual_decl(lines, i, line)
}

_virtual_decl(_, _, line) if regex.match(`\bvirtual\b[^~]*~`, line)

_virtual_decl(lines, i, _) if {
	i > 0
	trim_space(lines[i - 1]) == "virtual"
}

_class_re := `^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+(?:[A-Z][A-Z0-9_]*\s+)?([A-Za-z_]\w*)\s*(?:final\s*)?:\s*([^{};:][^{};]*?)\s*\{?\s*$`

# Base names in a base list: access specifiers, virtual, namespaces and
# template arguments removed.
_bases(list) := {b |
	some part in split(regex.replace(list, `<[^<>]*(?:<[^<>]*>[^<>]*)*>`, ""), ",")
	t := trim_space(regex.replace(part, `\b(?:public|protected|private|virtual)\b`, ""))
	segs := split(t, "::")
	b := trim_space(segs[count(segs) - 1])
	b != ""
}

findings contains finding if {
	count(_virtual_dtor) > 0
	some path, content in input.file_contents
	_cpp(path)
	contains(content, "~")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ":")
	regex.match(`\b(?:class|struct)\b`, line)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_class_re, line, 1)
	child := m[1]
	some parent in _bases(m[2])
	parent in _virtual_dtor
	parent != child
	dre := concat("", [`^\s*(?:inline\s+)?~`, child, `\s*\(`])
	some j in numbers.range(i + 1, min([i + 400, count(lines) - 1]))
	contains(lines[j], "~")
	regex.match(dre, lines[j])
	not regex.match(`\b(?:virtual|override|final)\b`, lines[j])
	not trim_space(lines[j - 1]) == "virtual"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("~%s() is declared without virtual or override although its parent %s declares a virtual destructor; mark it override (or virtual) so the declaration says that deleting through a %s pointer runs it, and so it stays virtual if the parent changes", [child, parent, parent]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}
