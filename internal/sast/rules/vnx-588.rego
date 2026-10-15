# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_588

import rego.v1

metadata := {
	"id": "VNX-588",
	"name": "Attempt to access child of a non-structure pointer",
	"description": "The address of a scalar variable (int, long, short, char, float, double, bool, size_t, the fixed-width integer types) cast to a structure pointer in C or C++: (struct header *)&flags, ((struct node *)&count)->next, (msg_hdr_t *)&word or (Packet *)&value or reinterpret_cast<Packet *>(&value) where the type is a struct or class, or a typedef of a struct or union, declared in the same file. The nearest declaration of the variable within the 60 lines above the cast (a local, a parameter or a global) must declare it as a scalar, so a structure of the same name declared nearer shadows a scalar further up. Accessing a member through such a pointer reads or writes memory outside the scalar. Not reported: casts of the address of a structure (the (struct sockaddr *)&addr socket idiom), of an array or array element, casts of a pointer value (void *, char *), scalars declared further away or in another file, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-588/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [588],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["pointer-cast-object", "cwe-588"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}

_lang(path) if {
	some ext in _exts
	endswith(path, ext)
}

_comment(line) if startswith(trim_space(line), "//")

_comment(line) if startswith(trim_space(line), "/*")

_comment(line) if startswith(trim_space(line), "*")

_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

# (struct T *)&name, the name not followed by [ . -> or ( (an element,
# member or call is a different object).
_c_cast_re := `\(\s*(?:(?:const|volatile)\s+)*struct\s+\w+\s*\*\s*(?:const\s*)?\)\s*&\s*([A-Za-z_]\w*)\s*(?:[^\w\s\[.(-]|$)`

# reinterpret_cast<T *>(&name)
_cpp_cast_re := `reinterpret_cast\s*<\s*(?:const\s+)?(?:struct\s+)?(\w+)\s*\*\s*>\s*\(\s*&\s*([A-Za-z_]\w*)\s*\)`

_scalar_types := `(?:int|long|short|char|float|double|bool|_Bool|size_t|ssize_t|off_t|u?int(?:8|16|32|64)_t|u?intptr_t|unsigned|signed)`

_cast_target(c, _) := m[1] if {
	contains(c, "struct")
	some m in regex.find_all_string_submatch_n(_c_cast_re, c, -1)
}

_cast_target(c, content) := m[2] if {
	contains(c, "reinterpret_cast")
	some m in regex.find_all_string_submatch_n(_cpp_cast_re, c, -1)
	_is_record_type(m[1], content)
}

# (T *)&name where T is a typedef'd struct or a struct/class declared in the
# same file.
_named_cast_re := `\(\s*(?:(?:const|volatile)\s+)*(\w+)\s*\*\s*(?:const\s*)?\)\s*&\s*([A-Za-z_]\w*)\s*(?:[^\w\s\[.(-]|$)`

_cast_target(c, content) := m[2] if {
	some m in regex.find_all_string_submatch_n(_named_cast_re, c, -1)
	_is_record_type(m[1], content)
}

_is_record_type(t, content) if regex.match(concat("", [`\b(?:struct|class)\s+`, t, `\s*(?::[^{;]*)?\{`]), content)

# typedef struct [tag] { ... } t;  and  typedef struct tag t;
_is_record_type(t, content) if {
	contains(content, "typedef")
	regex.match(concat("", [`(?m)^\s*\}\s*`, t, `\s*;`]), content)
	regex.match(`\btypedef\s+(?:struct|union)\b`, content)
}

_is_record_type(t, content) if regex.match(concat("", [`\btypedef\s+(?:struct|union)\s+\w+\s+\**`, t, `\s*;`]), content)

_not_type_words := {"return", "sizeof", "else", "case", "goto", "typeof", "delete", "new", "throw", "alignof", "decltype"}

# The nearest line above i (within 60) that declares name, of any type, must
# declare it as a scalar: a nearer struct declaration shadows a scalar of the
# same name in an earlier function.
_decl_line(lines, i, name) := k if {
	re := concat("", [`\b(\w+)\s*[*&]*\s*\b`, name, `\s*(?:\[[^\]]*\]\s*)*(?:=[^;]*)?[;,)]`])
	ks := [j |
		some j in numbers.range(max([0, i - 60]), i)
		contains(lines[j], name)
		not _comment(lines[j])
		some m in regex.find_all_string_submatch_n(re, _code(lines[j]), -1)
		not m[1] in _not_type_words
		j < i
	]
	count(ks) > 0
	k := max(ks)
}

_declared_scalar(lines, i, name) if {
	k := _decl_line(lines, i, name)
	re := concat("", [`\b`, _scalar_types, `\s+`, name, `\s*(?:=[^;]*)?[;,)]`])
	regex.match(re, _code(lines[k]))
}

# Declared on the same line as the cast (a parameter or earlier declarator).
_declared_scalar(lines, i, name) if {
	not _decl_line(lines, i, name)
	re := concat("", [`\b`, _scalar_types, `\s+`, name, `\s*(?:=[^;]*)?[;,)]`])
	regex.match(re, _code(lines[i]))
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "&")
	regex.match(`\w\s*\*\s*(?:const\s*)?\)\s*&\s*[A-Za-z_]|reinterpret_cast\s*<[^>\n]*\*\s*>\s*\(\s*&`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "&")
	not _comment(line)
	c := _code(line)
	name := _cast_target(c, content)
	_declared_scalar(lines, i, name)
	finding := {
		"rule_id": metadata.id,
		"message": "The address of a scalar variable is cast to a structure pointer: accessing a member through it reads or writes memory outside the variable. Declare a variable of the structure type, or copy the bytes with memcpy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
