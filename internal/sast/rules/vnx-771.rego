# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_771

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-771",
	"name": "Missing Reference to Active Allocated Resource",
	"description": "Reports C and C++ code that loses the only reference to memory it still owns. (1) `p = realloc(p, n)`: when realloc fails it returns NULL and leaves the old block allocated, and the assignment overwrites the only pointer to it (also through a cast or std::realloc, and for struct members such as `v->items`). (2) A pointer initialised or assigned from malloc, calloc, realloc, strdup, strndup or new that is assigned a fresh allocation again within the same function, up to 40 lines later, with no free/delete of it, no return, no copy to another variable and no hand-off to a function in between: the first block can no longer be reached. Not reported: realloc into a temporary that is checked before replacing the original, a pointer freed, returned, stored or passed to another function (other than mem*/str* and printf-style calls) before reassignment, reassignment in an alternative branch (else, case, #else, #elif) or inside the body of a failed-allocation check (if (p == NULL) { p = malloc(...) }; a check that returns, as in if (!p) return -1;, does not excuse a later reassignment), a declaration repeated by a loop, comments and string literals. Allocations that are simply never freed (CWE-401) are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-771/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [771],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["missing-reference-to-resource", "cwe-771"],
}

_ext(path) if regex.match(`\.(?:c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx)$`, path)

_alloc := `(?:(?:std::)?(?:malloc|calloc|realloc|strdup|strndup)\s*\(|\bnew\s+[\w:]+\s*[\[(])`

# p = realloc(p, ...), allowing a C cast or static_cast and std::
_realloc_re := `^\s*([A-Za-z_][\w.\->\[\]]*)\s*=\s*(?:\([^()]*\)\s*|(?:static|reinterpret)_cast<[^>]*>\s*\(\s*)?(?:std::)?realloc\s*\(\s*([A-Za-z_][\w.\->\[\]]*)\s*,`

# T *p = alloc(...) or p = alloc(...)
_assign_re := concat("", [`^\s*(?:(?:const\s+|unsigned\s+|struct\s+)?[\w:<>]+\s*\*+\s*|[\w:<>]+\s+\*?\s*)?([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*|(?:static|reinterpret)_cast<[^>]*>\s*\(\s*)?`, _alloc])

_reassign_re(v) := concat("", [`^\s*`, v, `\s*=\s*(?:\([^()]*\)\s*|(?:static|reinterpret)_cast<[^>]*>\s*\(\s*)?`, _alloc])

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	contains(content, "realloc")
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "realloc")
	not helpers.is_comment_line(raw)
	line := _strip_strings(raw)
	m := regex.find_all_string_submatch_n(_realloc_re, line, 1)
	count(m) > 0
	replace(m[0][1], " ", "") == replace(m[0][2], " ", "")
	finding := _finding(path, i, raw, sprintf("'%s = realloc(%s, ...)' loses the original block when realloc fails; assign to a temporary and check it first", [m[0][1], m[0][2]]))
}

_handed_off(l, v) if regex.match(concat("", [`\b(?:free|delete|kfree|g_free|zfree|release)\b\s*(?:\[\s*\])?\s*\(?\s*`, v, `\b`]), l)

_handed_off(l, v) if regex.match(concat("", [`\breturn\b.*\b`, v, `\b`]), l)

_handed_off(l, v) if regex.match(concat("", [`=\s*&?\s*`, v, `\s*;`]), l)

_handed_off(l, v) if {
	regex.match(concat("", [`[(,]\s*&?\s*`, v, `\s*[,)]`]), l)
	not regex.match(`^\s*(?:std::)?(?:mem(?:set|cpy|move|cmp)|str(?:n?cpy|n?cat|len|n?cmp|chr)|s?n?printf|fprintf|puts|fputs|sscanf|fgets|fread|read)\s*\(`, l)
}

_fn_end(lines, i) := e if {
	limit := min([count(lines) - 1, i + 40])
	ends := [k | some k in numbers.range(i + 1, limit); startswith(lines[k], "}")]
	e := min(array.concat([limit], ends))
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`(?:malloc|calloc|realloc|strdup|strndup)\s*\(|\bnew\s+[\w:]+\s*[\[(]`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "=")
	_alloc_word(raw)
	not helpers.is_comment_line(raw)
	line := _strip_strings(raw)
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	e := _fn_end(lines, i)
	some k in numbers.range(i + 1, e)
	regex.match(_reassign_re(v), lines[k])
	not _self_realloc(lines[k], v)
	not _released_between(lines, i, k, v)
	finding := _finding(path, i, raw, sprintf("'%s' is assigned a new allocation on line %d while this block is still unreleased; the first block becomes unreachable", [v, k + 1]))
}

_alloc_word(l) if contains(l, "alloc")

_alloc_word(l) if contains(l, "strdup")

_alloc_word(l) if contains(l, "strndup")

_alloc_word(l) if contains(l, "new ")

# p = realloc(p, ...) is reported by the first rule, not as an overwrite
_self_realloc(l, v) if regex.match(concat("", [`realloc\s*\(\s*`, v, `\s*,`]), l)

_released_between(lines, i, k, v) if {
	i + 1 <= k - 1
	some j in numbers.range(i + 1, k - 1)
	not helpers.is_comment_line(lines[j])
	_handed_off(lines[j], v)
}

# The two assignments sit in alternative branches.
_released_between(lines, i, k, _) if {
	i + 1 <= k - 1
	some j in numbers.range(i + 1, k - 1)
	regex.match(`^\s*(?:\}\s*)?else\b|^\s*case\b|^\s*default\s*:|^\s*#\s*(?:else|elif)\b`, lines[j])
}

# The second allocation only runs when the first one failed: it sits in the
# body of an `if (!p)` / `if (p == NULL)` up to three lines above, with no
# return or jump in between (`if (!p) return -1;` guards the code after it
# and does not make a later reassignment safe).
_released_between(lines, i, k, v) if {
	some j in numbers.range(max([i, k - 3]), k - 1)
	regex.match(concat("", [`!\s*`, v, `\b|\b`, v, `\s*==\s*(?:NULL|nullptr|0)\b|\b(?:NULL|nullptr)\s*==\s*`, v, `\b`]), lines[j])
	not _jump_between(lines, j, k - 1)
}

_jump_between(lines, a, b) if {
	some m in numbers.range(a, b)
	regex.match(`\b(?:return|goto|break|continue|exit|abort)\b`, lines[m])
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
