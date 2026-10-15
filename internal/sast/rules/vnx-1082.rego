# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1082

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1082",
	"name": "Class Instance Self Destruction Control Element",
	"description": "A C++ member function that destroys the object it is running on: `delete this;` (also `::delete this;`, `delete (this);` and `delete static_cast<D*>(this);`), `std::destroy_at(this)`, or an explicit call of the object's own destructor (`this->~T()`, `(*this).~T()`, including the placement-new reassignment idiom). Any use of the object after the call, by the method itself or by a caller still holding a pointer or reference, is a use after free, and `delete this` on an object that was not allocated with plain `new` (a stack, member, array or placement object) is undefined behaviour. Intrusive reference counting (`if (--refs == 0) delete this;`) is reported too, because it is the same construct; review that the object is always heap-allocated and never touched after the release. Not reported: deleting another object or a member (`delete this->buf_`, `delete other`), destroying a different object explicitly (`item->~Item()` in a pool), destructor definitions, and the text inside comments or string literals. Java, Python and other managed languages have no self-destruction construct, so only C++ is checked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1082/",
	"languages": ["cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1082],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["self-destruction", "delete-this", "object-lifetime", "cwe-1082"],
}

_is_cpp(path) if regex.match(`\.(cpp|cc|cxx|c\+\+|hpp|hh|hxx|h|ipp|inl|tpp)$`, path)

# Removes string and character literals so their text never matches.
_strip_literals(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# Removes a trailing // comment and any /* ... */ on the line.
_strip_comments(line) := regex.replace(regex.replace(line, `/\*.*?\*/`, ""), `//.*$`, "")

_delete_this_re := `\bdelete\s*(?:\(\s*this\s*\)|this\b|(?:static|reinterpret|dynamic|const)_cast\s*<[^;]*>\s*\(\s*this\s*\))\s*;`

_self_destroy_re := `\bdelete\s*(?:\(\s*this\s*\)|this\b|(?:static|reinterpret|dynamic|const)_cast\s*<[^;]*>\s*\(\s*this\s*\))\s*;|\bdestroy_at\s*\(\s*this\s*\)|\bthis\s*->\s*~\s*[A-Za-z_]\w*\s*\(|\(\s*\*\s*this\s*\)\s*\.\s*~\s*[A-Za-z_]\w*\s*\(`

_what(code) := "deletes the object it is running on (`delete this`)" if regex.match(_delete_this_re, code)

_what(code) := "calls its own destructor explicitly" if {
	not regex.match(_delete_this_re, code)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_cpp(path)
	regex.match(`\bdelete\b[^;\n]*\bthis\b|~\s*[A-Za-z_]\w*\s*\(|\bdestroy_at\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bthis\b`, line)
	not helpers.is_comment_line(line)
	code := _strip_comments(_strip_literals(line))
	regex.match(_self_destroy_re, code)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Member function %s; any later use of the object is a use after free", [_what(code)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
