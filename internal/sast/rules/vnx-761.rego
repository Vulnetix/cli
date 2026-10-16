# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_761

import rego.v1

import data.vulnetix.helpers



metadata := {
	"id": "VNX-761",
	"name": "free() of a pointer that is not at the start of its buffer",
	"description": "free() (or std::free) is given a pointer into the middle of an allocation instead of the pointer the allocator returned, which corrupts the heap. Reported: (1) free(p + n), free(s->data + s->off), free((void *)(p + 1)), free(&buf[i]) with a non-zero index, and free(++p); (2) a local pointer assigned from malloc, calloc, realloc, strdup or strndup (also through a C cast, static_cast/reinterpret_cast or std::), then advanced in the same function (p++, ++p, *p++ = ..., p += n, p = p + n), then passed to free() with no assignment, p -= or p-- that moves it back in between. Not reported: free(ptr - HEADER) (the allocator-wrapper idiom of stepping back over a prefix), a separate cursor that walks the buffer while the original pointer is freed, free(items[i]), free(items[i + 1]) and free(*(p + i)) (elements, not offsets), *p += n and (*p)++ (the value changes, not the pointer), a parameter or local of the same name declared after the allocation (another method of a class body), free(&buf[0]), wrappers such as sdsfree/zfree/my_free, comments and string literals. Releases of addresses that never came from the heap are VNX-763; mismatched allocators are VNX-762.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-761/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [761],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["memory", "free-pointer-not-at-start", "cwe-761"],
}

_is_c(path) if regex.match(`\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$`, path)

# free( not preceded by an identifier character, '.', or '->' (my_free, obj.free).
_free := `(?:^|[^\w.>])(?:std::)?free\s*\(`

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(_free, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "free")
	not _is_comment(line)
	code := _strip_strings(line)
	regex.match(_free, code)
	_offset_free(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "free() of a pointer that is not the start of its allocation: pass free() exactly the pointer malloc/calloc/realloc returned (keep a separate cursor for walking the buffer)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_cast := `(?:\(\s*(?:const\s+)?[A-Za-z_][\w\s]*\*+\s*\)\s*)?`

# free(p + n), free((void *)(p + 1)). Subscripts are blanked first, so the
# arithmetic in free(items[i + 1]) selects an element and is not an offset.
_offset_free(_, _, code) if {
	regex.match(concat("", [_free, `\s*`, _cast, `\(?\s*[A-Za-z_][\w.\->\[\]]*\s*\+\s*[\w(]`]), _blank_subscripts(code))
}

_blank_subscripts(code) := regex.replace(regex.replace(code, `\[[^\[\]]*\]`, "[]"), `\[[^\[\]]*\]`, "[]")

# free(++p)
_offset_free(_, _, code) if {
	regex.match(concat("", [_free, `\s*\+\+\s*[A-Za-z_]`]), code)
}

# free(&buf[i]) with i != 0
_offset_free(_, _, code) if {
	some m in regex.find_all_string_submatch_n(concat("", [_free, `\s*&\s*[A-Za-z_][\w.\->]*\s*\[\s*([^\]]+?)\s*\]\s*\)`]), code, -1)
	m[1] != "0"
}

# p = malloc(...); ... p++; ... free(p);
_offset_free(lines, i, code) if {
	m := regex.find_all_string_submatch_n(concat("", [_free, `\s*([A-Za-z_]\w*)\s*\)`]), code, 1)
	count(m) > 0
	p := m[0][1]
	start := max([0, i - 60])
	alloc_re := concat("", [`\b`, p, `\s*=\s*(?:\([^)]*\)\s*|(?:static|reinterpret)_cast\s*<[^>]*>\s*\(\s*)?(?:std::)?(?:malloc|calloc|realloc|strdup|strndup|xmalloc|xcalloc)\s*\(`])
	allocs := [j | some j in numbers.range(start, i - 1); j < i; regex.match(alloc_re, lines[j])]
	count(allocs) > 0
	a := max(allocs)
	not _function_ends(lines, a, i)
	not _redeclared_between(lines, a, i, p)
	# p++ and *p++ advance the pointer; *p += n changes the value it points to.
	advance_re := concat("", [`(?:\b`, p, `\s*\+\+|(?:^|[^*\w.>])`, p, `\s*\+=|\+\+\s*`, p, `\b|\b`, p, `\s*=\s*`, p, `\s*\+)`])
	advances := [k |
		some k in helpers.span(a + 1, i - 1)
		k >= a + 1
		k <= i - 1
		regex.match(advance_re, lines[k])
		not _is_comment(lines[k])
	]
	count(advances) > 0
	last := max(advances)
	not _moved_back(lines, last, i, p)
}

# The pointer is assigned, decremented or stepped back after its last advance.
_moved_back(lines, last, i, p) if {
	back_re := concat("", [`(?:^|[^*\w.>]|\w\s*\*+\s*)`, p, `\s*(?:=[^=]|-=|--)|--\s*`, p, `\b`])
	some k in helpers.span(last + 1, i - 1)
	k >= last + 1
	k <= i - 1
	regex.match(back_re, lines[k])
	not regex.match(concat("", [`\b`, p, `\s*=\s*`, p, `\s*\+`]), lines[k])
}

# A parameter or local of the same name declared between the allocation and the
# free is another variable (a second method in a class body, whose closing
# brace is indented and so not seen by _function_ends).
_redeclared_between(lines, a, i, p) if {
	decl_re := concat("", [`\w\s*\*+\s*`, p, `\s*(?:=[^=]|;|,|\))`])
	some k in helpers.span(a + 1, i - 1)
	k >= a + 1
	k <= i - 1
	regex.match(decl_re, lines[k])
}

# A column-0 closing brace between the allocation and the free: another function.
_function_ends(lines, a, i) if {
	some k in helpers.span(a + 1, i - 1)
	k >= a + 1
	k <= i - 1
	startswith(lines[k], "}")
}

# A C comment line. Not helpers.is_comment_line: that treats every line
# starting with '*' as a block-comment continuation, and `*out++ = c;` is code.
_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)
