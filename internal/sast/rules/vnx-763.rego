# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_763

import rego.v1

metadata := {
	"id": "VNX-763",
	"name": "Release of a pointer that never came from the heap",
	"description": "free() or delete is given an address the allocator never returned: the address of a variable, a stack or static array, or a string literal. Releasing it is undefined behaviour and corrupts the allocator's state. Reported: free(&x) and free((void *)&x) for a plain identifier x (not &x[0], not a member access); free(arr) and delete[] arr where arr is declared as an array in the same function (no column-0 closing brace between the declaration and the release) or as an array at file scope, including arrays of pointers; free(\"literal\"); and C++ delete &x. Not reported: pointers assigned from an allocator, &p[0], array parameters (char buf[] is a pointer), struct members, wrappers such as sdsfree, an array of the same name in a different function or shadowed by a pointer of that name declared after it (a later method of a class body), comments and string literals. Pointers into the middle of an allocation are VNX-761; mismatched allocators are VNX-762; releasing the same pointer twice is VNX-415.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-763/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [763],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["memory", "release-of-invalid-pointer", "cwe-763"],
}

_is_c(path) if regex.match(`\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$`, path)

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_free := `(?:^|[^\w.>])(?:std::)?free\s*\(\s*`

_cast := `(?:\(\s*(?:const\s+)?[A-Za-z_][\w\s]*\*+\s*\)\s*)?`

_gate := `(?:^|[^\w.>])(?:free\s*\(|delete\b)`

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not _is_comment(line)
	code := _strip_strings(line)
	some what in _invalid(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Release of %s, which was never returned by an allocator: only free()/delete what malloc/new returned", [what]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_invalid(lines, i, code) := ({"the address of a variable" |
	regex.match(concat("", [_free, _cast, `&\s*[A-Za-z_]\w*\s*\)`]), code)
} | {"the address of a variable" |
	regex.match(`(?:^|[^\w.>])delete\s+&\s*[A-Za-z_]\w*\s*;`, code)
}) | ({"a string literal" |
	regex.match(concat("", [_free, _cast, `""\s*\)`]), code)
} | {"an array that is not heap memory" |
	some name in _released_names(code)
	_is_array(lines, i, name)
})

_released_names(code) := {m[1] | some m in regex.find_all_string_submatch_n(concat("", [_free, `([A-Za-z_]\w*)\s*\)`]), code, -1)} | {m[1] | some m in regex.find_all_string_submatch_n(`(?:^|[^\w.>])delete\s*(?:\[\s*\]\s*)?([A-Za-z_]\w*)\s*;`, code, -1)}

# An array declaration: type, optional pointer stars, the name, one or more
# [dimensions], an optional initialiser and the semicolon. A parameter list
# (char buf[]) has no semicolon after the brackets.
_array_decl := `^(\s*)(?:(?:static|const|volatile|unsigned|signed|register|struct|union|enum)\s+)*[A-Za-z_][\w:]*(?:\s*\*+\s*|\s+\**\s*)([A-Za-z_]\w*)\s*\[[^\]]*\](?:\s*\[[^\]]*\])*\s*(?:=[^=;][^;]*)?;`

# Arrays declared at file scope (column 0), computed once per file.
_file_arrays(lines) := {m[0][2] |
	some l in lines
	contains(l, "[")
	not _keyword_stmt(l)
	m := regex.find_all_string_submatch_n(_array_decl, l, 1)
	count(m) > 0
	m[0][1] == ""
}

_is_array(lines, i, name) if {
	name in _file_arrays(lines)
	not _local_pointer(lines, i, name)
}

# Declared as an array in the enclosing function.
_is_array(lines, i, name) if {
	cands := [j |
		some j in numbers.range(max([0, i - 200]), i - 1)
		j >= max([0, i - 200])
		j <= i - 1
		contains(lines[j], name)
		m := regex.find_all_string_submatch_n(_array_decl, lines[j], 1)
		count(m) > 0
		m[0][2] == name
		m[0][1] != ""
		not _keyword_stmt(lines[j])
	]
	count(cands) > 0
	a := max(cands)
	not _function_ends(lines, a, i)
	not _pointer_declared_between(lines, a, i, name)
}

# A pointer of the same name declared after the array is another variable: a
# second method in a class body, whose closing brace is indented.
_pointer_declared_between(lines, a, i, name) if {
	ptr_re := concat("", [`\w\s*\*+\s*`, name, `\s*(?:=[^=]|;|,|\))`])
	some k in numbers.range(a + 1, i - 1)
	k >= a + 1
	k <= i - 1
	regex.match(ptr_re, lines[k])
}

# A local pointer of the same name shadows the file-scope array.
_local_pointer(lines, i, name) if {
	ptr_re := concat("", [`\*\s*`, name, `\s*(?:=|;|,|\))`])
	some j in numbers.range(max([0, i - 200]), i - 1)
	j >= max([0, i - 200])
	j <= i - 1
	contains(lines[j], name)
	regex.match(ptr_re, lines[j])
}

_function_ends(lines, a, i) if {
	some k in numbers.range(a + 1, i - 1)
	k >= a + 1
	k <= i - 1
	startswith(lines[k], "}")
}

# `return buf[i] == x;` and `else buf[i] = 0;` are statements, not declarations.
_keyword_stmt(line) if regex.match(`^\s*(?:return|delete|else|case|goto|throw|sizeof|co_return|co_yield)\b`, line)
