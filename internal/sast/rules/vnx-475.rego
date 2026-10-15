# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_475

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-475",
	"name": "Undefined Behavior for Input to API",
	"description": "C or C++ calls whose arguments put the library function outside its defined behaviour: a copy whose source and destination are the same object (memcpy, strcpy, strncpy, strcat, strncat, wcscpy, wcscat with the same base pointer on both sides, such as `memcpy(buf, buf + 1, n)`, `strcpy(path, path + 2)`, `memcpy(s->data + off, s->data, n)`); sprintf/snprintf/vsprintf whose destination buffer is also one of its own arguments (`sprintf(buf, \"%s/%s\", buf, file)`); fflush(stdin), which the C standard leaves undefined for input streams; and a literal NULL passed where a string or object pointer is required (a printf-family call with %s and a NULL argument, memcpy/strlen/strcmp/strcpy and the other mem*/str* functions with a NULL argument, which is undefined even with a zero length). Not reported: snprintf(NULL, 0, ...) used to measure the output length, copies between different elements of one array of strings or structs (`strcpy(names[i], names[j])`, `strcpy(users[i].name, users[j].name)`), memmove, copies between different objects or different members (p->a and p->b), sprintf whose destination appears only inside another call such as strlen(buf), fflush of output streams, guarded NULL tests, test sources, comments and string literals. Signed overflow such as INT_MAX + 1 is CWE-190, and ctype functions applied to plain char are not judged (the argument's type is rarely visible on the line).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-475/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [475],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["undefined-behavior-api", "cwe-475"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_code(line) := regex.replace(
	regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `/\*.*?\*/`, " "),
	`//.*$`, "",
)

_pre := `(?:^|[^\w.>]|std::)`

# The object an argument points into: casts removed, offsets ignored.
# `(const char *)s->data + off` -> s->data. With `&` the subscript is an
# offset into the same buffer (`&buf[1]` -> buf); without it the subscripted
# element is itself the object (`names[i]`, `users[j].name`), so the
# subscript is kept and two different elements stay two objects.
_base(arg) := b if {
	m := regex.find_all_string_submatch_n(`^\s*(?:\([^()]*\)\s*)*&\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*(?:$|[+\-\[)\s])`, arg, 1)
	count(m) > 0
	b := regex.replace(m[0][1], `\s+`, "")
}

_base(arg) := b if {
	not regex.match(`^\s*(?:\([^()]*\)\s*)*&`, arg)
	m := regex.find_all_string_submatch_n(`^\s*(?:\([^()]*\)\s*)*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*|\s*\[[^\[\]]*\])*)\s*(?:$|[+\-)\s])`, arg, 1)
	count(m) > 0
	b := regex.replace(m[0][1], `\s+`, "")
}

_copy_re := concat("", [_pre, `(?:memcpy|strcpy|strncpy|strcat|strncat|wcscpy|wcsncpy|wcscat)\s*\(\s*([^,]+),([^,]+)(?:,([^;]*))?`])

# Two different elements of one array copied one element at a time
# (`memcpy(&a[i], &a[j], sizeof *a)`) do not overlap.
_element_copy(m) if {
	trim_space(m[1]) != trim_space(m[2])
	regex.match(`^\s*sizeof\b[^,]*\)?\s*\)?\s*;?\s*$`, m[3])
}

_overlap(code) if {
	some m in regex.find_all_string_submatch_n(_copy_re, code, -1)
	b := _base(m[1])
	b == _base(m[2])
	not _element_copy(m)
}

_print_re := concat("", [_pre, `(?:sn?printf|vsn?printf)\s*\((.*)$`])

_self_print(code) if {
	some m in regex.find_all_string_submatch_n(_print_re, code, -1)
	args := split(m[1], ",")
	count(args) > 2
	dst := _base(args[0])
	some k, a in args
	k > 1
	not contains(a, `""`)
	_base(a) == dst
}

_fflush_stdin(code) if regex.match(concat("", [_pre, `fflush\s*\(\s*stdin\s*\)`]), code)

# NULL as one of the call's own arguments (no nested call in between).
_null_arg := `\(\s*(?:[^()]*,)?\s*NULL\s*(?:,|\))`

_null_string(code, raw) if {
	regex.match(concat("", [_pre, `(?:[fs]n?|v[fs]?n?)?printf\s*`, _null_arg]), code)

	# snprintf(NULL, 0, ...) is the standard way to measure the output.
	not regex.match(`v?snprintf\s*\(\s*NULL\s*,\s*0\s*,[^()]*\)`, code)
	contains(raw, "%s")
}

_null_string(code, _) if regex.match(concat("", [_pre, `(?:memcpy|memmove|memcmp|memchr|memset|strcpy|strncpy|strcat|strncat|strlen|strcmp|strncmp|strchr|strrchr|strstr|strdup)\s*`, _null_arg]), code)

_kind(code, _) := "overlap" if _overlap(code)

_kind(code, _) := "self-print" if {
	not _overlap(code)
	_self_print(code)
}

_kind(code, _) := "fflush" if _fflush_stdin(code)

_kind(code, raw) := "null" if {
	not _overlap(code)
	not _self_print(code)
	_null_string(code, raw)
}

_messages := {
	"overlap": "Source and destination of this copy are the same object: memcpy/strcpy/strcat on overlapping memory is undefined behaviour. Use memmove, or copy through a separate buffer",
	"self-print": "The destination buffer of sprintf/snprintf is also one of its arguments: reading and writing the same buffer in one call is undefined behaviour. Format into a separate buffer",
	"fflush": "fflush(stdin) is undefined behaviour in standard C (only some C libraries define it for input). Read and discard the pending input instead",
	"null": "A literal NULL is passed where the function requires a valid pointer (a %s argument, or a mem*/str* pointer argument): undefined behaviour, even with a zero length",
}

# A call whose arguments continue on the next lines is read up to its `;`
# (at most four lines), so `sprintf(out,\n "%s/%s", out, name);` is one call.
_stmt(_, _, line) := line if contains(line, ";")

_stmt(lines, i, line) := s if {
	not contains(line, ";")
	s := split(concat(" ", array.slice(lines, i, i + 4)), ";")[0]
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(`(?:mem|str|wcs)[a-z]*\s*\(|printf\s*\(|fflush\s*\(\s*stdin`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	regex.match(`(?:mem|str|wcs)[a-z]*\s*\(|printf\s*\(|fflush`, line)
	not helpers.is_comment_line(line)
	stmt := _stmt(lines, i, line)
	k := _kind(_code(stmt), stmt)
	finding := {
		"rule_id": metadata.id,
		"message": _messages[k],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
