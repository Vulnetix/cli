# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_762

import rego.v1

metadata := {
	"id": "VNX-762",
	"name": "Memory released with a routine that does not match its allocator",
	"description": "A pointer is released by a routine that does not pair with the one that allocated it, which is undefined behaviour and typically corrupts the heap or skips destructors. Reported, for a local pointer whose most recent assignment in the same function (within 100 lines, no column-0 closing brace in between) is the allocation: new T[n] released with free() or scalar delete; new T released with free() or delete[]; malloc, calloc, realloc, reallocarray, strdup or strndup memory (also through a C cast, static_cast/reinterpret_cast or std::) released with delete or delete[]; alloca stack memory passed to free(). Also reported: std::unique_ptr<T> or std::shared_ptr<T> (T not an array type) constructed from new T[n], which releases the array with scalar delete. Not reported: matching pairs, a pointer reassigned from another allocator before the release, a release in a different function (including a later method of a class body that takes a parameter of the same name), placement new, unique_ptr<T[]>, identifiers that merely contain 'new' (new_buf), comments and string literals. Offset pointers are VNX-761; addresses that never came from the heap are VNX-763.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-762/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [762],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["memory", "mismatched-memory-mgmt", "cwe-762"],
}

_is_c(path) if regex.match(`\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$`, path)

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_free := `(?:^|[^\w.>])(?:std::)?free\s*\(\s*([A-Za-z_]\w*)\s*\)`

_delete := `(?:^|[^\w.>])delete\s+([A-Za-z_]\w*)\s*;`

_delete_arr := `(?:^|[^\w.>])delete\s*\[\s*\]\s*([A-Za-z_]\w*)\s*;`

_release_gate := `(?:^|[^\w.>])(?:free\s*\(|delete\b)`

_release(code) := {["free", m[1]] | some m in regex.find_all_string_submatch_n(_free, code, -1)} | {["delete", m[1]] | some m in regex.find_all_string_submatch_n(_delete, code, -1)} | {["delete[]", m[1]] | some m in regex.find_all_string_submatch_n(_delete_arr, code, -1)}

_mismatch := {
	"free": {"new[]", "new", "alloca"},
	"delete": {"new[]", "malloc", "alloca"},
	"delete[]": {"new", "malloc", "alloca"},
}

_alloc_name := {"new[]": "new[]", "new": "new", "malloc": "malloc()", "alloca": "alloca()"}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`\bnew\b|\bdelete\b|alloca\s*\(`, content)
	regex.match(_release_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_release_gate, line)
	not _is_comment(line)
	code := _strip_strings(line)
	some rel in _release(code)
	kind := _alloc_kind(lines, i, rel[1])
	kind in _mismatch[rel[0]]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Memory from %s released with %s: use the matching routine (new/delete, new[]/delete[], malloc/free; never free alloca memory)", [_alloc_name[kind], rel[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "_ptr<")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "_ptr<")
	not _is_comment(line)
	regex.match(`\b(?:unique|shared)_ptr\s*<\s*[\w:]+(?:\s*\*)?\s*>\s*(?:[A-Za-z_]\w*\s*)?[({=]\s*(?:std::(?:unique|shared)_ptr\s*<[^>]*>\s*\(\s*)?new\s+[\w:]+\s*\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Smart pointer to a single object owns an array from new[]: its scalar delete does not match. Use std::unique_ptr<T[]> (or std::vector)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The kind of the most recent assignment to p above line i, in the same function.
_alloc_kind(lines, i, p) := kind if {
	assign_re := concat("", [`(?:^|[^*\w.>]|\w\s*\*+\s*)`, p, `\s*=[^=]`])
	cands := [j |
		some j in numbers.range(max([0, i - 100]), i - 1)
		j >= max([0, i - 100])
		j <= i - 1
		regex.match(assign_re, lines[j])
		not _is_comment(lines[j])
	]
	count(cands) > 0
	a := max(cands)
	not _function_ends(lines, a, i)
	not _redeclared_between(lines, a, i, p)
	kind := _classify(lines[a], p)
}

# A parameter or local of the same name declared after the allocation is another
# variable: void flush(char *buf) in a second method of a class body, whose
# closing brace is indented and so not seen by _function_ends.
_redeclared_between(lines, a, i, p) if {
	decl_re := concat("", [`\w\s*\*+\s*`, p, `\s*(?:;|,|\))`])
	some k in numbers.range(a + 1, i - 1)
	k >= a + 1
	k <= i - 1
	regex.match(decl_re, lines[k])
}

_classify(line, p) := "new[]" if {
	regex.match(concat("", [`\b`, p, `\s*=\s*new\s+(?:\(\s*std::nothrow\s*\)\s*)?[\w:<>\s\*]+?\[`]), line)
} else := "new" if {
	regex.match(concat("", [`\b`, p, `\s*=\s*new\s+(?:\(\s*std::nothrow\s*\)\s*)?[\w:<>]+(?:\s*\*)?\s*(?:\(|\{|;)`]), line)
} else := "malloc" if {
	regex.match(concat("", [`\b`, p, `\s*=\s*`, _c_cast, `(?:std::)?(?:malloc|calloc|realloc|reallocarray|strdup|strndup)\s*\(`]), line)
} else := "alloca" if {
	regex.match(concat("", [`\b`, p, `\s*=\s*`, _c_cast, `(?:alloca|_alloca|__builtin_alloca)\s*\(`]), line)
}

# (char *)malloc(n), static_cast<char *>(std::malloc(n))
_c_cast := `(?:\([^)]*\)\s*|(?:static|reinterpret)_cast\s*<[^>]*>\s*\(\s*)?`

_function_ends(lines, a, i) if {
	some k in numbers.range(a + 1, i - 1)
	k >= a + 1
	k <= i - 1
	startswith(lines[k], "}")
}
