# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1098

import rego.v1

metadata := {
	"id": "VNX-1098",
	"name": "Data Element containing Pointer Item without Proper Copy Control Element",
	"description": "A C++ class owns memory through a raw pointer (its destructor releases it with delete, delete[] or free()) but declares no copy constructor. The compiler then generates a shallow copy that duplicates the pointer, so the first copy destroyed frees memory the other still uses: a double free or use-after-free when the object is passed or returned by value or stored in a container (the rule of three). Reported: the destructor, inline (~Name() { delete p; }) or out of line (Name::~Name()). Not reported: classes that declare a copy constructor, including a deleted one (Name(const Name&) = delete) and a template one (Name(const Name<T>&)), classes deriving from QObject or another Qt QObject type (which deletes its copy), declare a move constructor or move assignment (which suppresses the implicit copy), are marked non-copyable (boost::noncopyable, DISALLOW_COPY_AND_ASSIGN, Q_DISABLE_COPY and similar), destructors that release nothing, and comments. A copy constructor declared in another file of the scan counts. Smart-pointer members need no destructor and are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1098/",
	"languages": ["cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1098],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["cpp", "rule-of-three", "memory", "double-free", "cwe-1098"],
}

_cpp_ext(path) if regex.match(`\.(cpp|cc|cxx|c\+\+|hpp|hh|hxx|h|ipp|inl)$`, path)

_is_comment(line) if startswith(trim_space(line), "//")

_is_comment(line) if startswith(trim_space(line), "*")

_is_comment(line) if startswith(trim_space(line), "/*")

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Out-of-line Name::~Name( or in-class ~Name(.
_dtor_name(line) := n if {
	m := regex.find_all_string_submatch_n(`^\s*(?:template\s*<[^>]*>\s*)?(?:inline\s+)?(?:\w+(?:<[^>]*>)?::)*(\w+)(?:<[^>]*>)?::~(\w+)\s*\(`, line, 1)
	count(m) > 0
	m[0][1] == m[0][2]
	n := m[0][1]
}

_dtor_name(line) := n if {
	not contains(line, "::~")
	m := regex.find_all_string_submatch_n(`^\s*(?:virtual\s+)?~(\w+)\s*\(\s*(?:void\s*)?\)`, line, 1)
	count(m) > 0
	n := m[0][1]
}

# The destructor body releases memory: from its line to the first '}' at its
# indent, at most 20 lines.
_releases(lines, i) if {
	not regex.match(`=\s*(default|delete)\s*;`, lines[i])
	end := min([count(lines) - 1, i + 20])
	ends := [m | some m in numbers.range(i + 1, end); i + 1 <= end; _indent(lines[m]) <= _indent(lines[i]); startswith(trim_space(lines[m]), "}")]
	e := min(array.concat([end], ends))
	some k in numbers.range(i, e)
	not _is_comment(lines[k])
	regex.match(`\bdelete\s*(\[\s*\])?\s*[\w\(\*]|\bfree\s*\(`, lines[k])
	not regex.match(`=\s*delete\s*;`, lines[k])
}

_copy_controlled(name) if {
	some _, c in input.file_contents
	contains(c, name)
	regex.match(concat("", [`\b`, name, `\s*\(\s*(?:const\s+)?`, name, `\s*(?:<[^()]*>\s*)?(?:const\s*)?&`]), c)
}

# QObject and its subclasses delete their copy constructor.
_copy_controlled(name) if {
	some _, c in input.file_contents
	contains(c, name)
	regex.match(concat("", [`\b(class|struct)\s+`, name, `\b[^;{]*:\s*(?:public\s+|protected\s+|private\s+)?Q(?:Object|Widget|Dialog|MainWindow|Thread|AbstractItemModel|AbstractListModel|AbstractTableModel|Frame|GraphicsItem|GraphicsObject|QuickItem)\b`]), c)
}

_copy_controlled(name) if {
	some _, c in input.file_contents
	contains(c, name)
	regex.match(concat("", [`\b`, name, `\s*\(\s*`, name, `\s*(?:<[^()]*>\s*)?&&|operator\s*=\s*\(\s*`, name, `\s*(?:<[^()]*>\s*)?&&`]), c)
}

_copy_controlled(name) if {
	some _, c in input.file_contents
	contains(c, name)
	regex.match(concat("", [`(?i)(DISALLOW_COPY\w*|DISABLE_COPY\w*|NON_?COPYABLE\w*|NO_COPY\w*)\s*\(\s*`, name, `\s*\)`]), c)
}

_copy_controlled(name) if {
	some _, c in input.file_contents
	contains(c, name)
	regex.match(concat("", [`\b(class|struct)\s+`, name, `\b[^;{]*:[^;{]*(?i:non_?copyable|uncopyable)`]), c)
}

findings contains finding if {
	some path, content in input.file_contents
	_cpp_ext(path)
	contains(content, "~")
	regex.match(`\bdelete\b|\bfree\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "~")
	not _is_comment(line)
	name := _dtor_name(line)
	_releases(lines, i)
	not _copy_controlled(name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s releases owned memory in its destructor but declares no copy constructor; the implicit shallow copy shares the pointer and causes a double free. Define or delete the copy constructor and copy assignment, or hold the memory in std::unique_ptr/std::vector", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
