# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_628

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-628",
	"name": "Function Call with Incorrectly Specified Arguments",
	"description": "C and C++ library calls whose arguments are wrong in a way visible on the call line: memset()/wmemset() with the fill value and the length transposed (a literal 0 length after a non-zero value, so nothing is cleared); printf, fprintf, sprintf, snprintf, dprintf and syslog with a literal format whose conversion count (including * width and precision) differs from the number of arguments that follow, so the call reads arguments that were never passed or silently drops one; and open()/openat() with O_CREAT but no mode argument, so the new file's permissions come from whatever is on the stack. Not reported: calls split over several lines, formats built from macros (PRIu64) or positional %n$ conversions, wrapper functions with their own format conventions, memset(p, 0, 0), open() with a mode, and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-628/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [628],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["printf-format", "memset", "open-mode", "cwe-628"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# ── memset with value and length transposed ──────────────────────────────

_memset_re := `\b(?:memset|wmemset)\s*\(\s*[^,]+,\s*([^,]+?)\s*,\s*(?:0|0x0|0L|0U|0UL)\s*\)`

_bad(line, code) if {
	contains(code, "memset")
	m := regex.find_all_string_submatch_n(_memset_re, line, 1)
	count(m) > 0
	not regex.match(`^(0|0x0+|'\\0'|NULL|\(char\)\s*0)$`, m[0][1])
}

# ── open(..., O_CREAT) with no mode ──────────────────────────────────────

_bad(_, code) if {
	contains(code, "O_CREAT")
	regex.match(`(^|[^\w.>])open\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*[^,()]*\bO_(CREAT|TMPFILE)\b[^,()]*\)`, code)
}

_bad(_, code) if {
	contains(code, "O_CREAT")
	regex.match(`(^|[^\w.>])openat\s*\(\s*[^,()]+,\s*[^,()]+(?:\([^()]*\))?\s*,\s*[^,()]*\bO_(CREAT|TMPFILE)\b[^,()]*\)`, code)
}

# ── printf family: conversions vs arguments ──────────────────────────────

_fmt_res := [
	`(?:^|[^\w.>])(?:std::)?(?:printf|wprintf)\s*\(\s*L?"((?:\\.|[^"\\])*)"(.*)$`,
	`(?:^|[^\w.>])(?:std::)?(?:fprintf|sprintf|dprintf|syslog|fwprintf)\s*\(\s*[^,"()]+(?:\([^()]*\))?\s*,\s*L?"((?:\\.|[^"\\])*)"(.*)$`,
	`(?:^|[^\w.>])(?:std::)?(?:snprintf|swprintf)\s*\(\s*[^,"()]+,\s*[^,"()]+(?:\([^()]*\))?\s*,\s*L?"((?:\\.|[^"\\])*)"(.*)$`,
]

_spec_re := `%[-+ #0']*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|L|z|j|t|q|I64|I32)?[diouxXeEfFgGaAcspnCS]`

_needed(fmt) := n if {
	f := replace(fmt, "%%", "")
	not regex.match(`%\d+\$`, f)
	specs := regex.find_all_string_submatch_n(_spec_re, f, -1)
	stars := count([1 | some s in specs; s[1] == "*"]) + count([1 | some s in specs; s[2] == "*"])
	count(indexof_n(f, "%")) == count(specs) + count(indexof_n(f, "%m"))
	n := count(specs) + stars
}

_strip_nested(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "_"), `\([^()]*\)`, "_"), `\([^()]*\)`, "_")

_given(rest) := n if {
	r := _blank(rest)
	m := regex.find_all_string_submatch_n(`^\s*(?:,(.*))?\)\s*;\s*(?://.*|/\*.*)?$`, r, 1)
	count(m) > 0
	args := _strip_nested(regex.replace(m[0][1], `\{[^{}]*\}`, ""))
	not contains(args, "(")
	not contains(args, ")")
	n := _count_args(args)
}

_count_args(a) := 0 if trim_space(a) == ""

_count_args(a) := count(split(a, ",")) if trim_space(a) != ""

_bad(line, code) if {
	contains(code, "printf(")
	_printf_mismatch(line)
}

_bad(line, code) if {
	contains(code, "syslog")
	_printf_mismatch(line)
}

_printf_mismatch(line) if {
	some re in _fmt_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	need := _needed(m[0][1])
	got := _given(m[0][2])
	need != got
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`memset|printf|O_CREAT|syslog`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`memset|printf|O_CREAT|syslog`, line)
	not helpers.is_comment_line(line)
	_bad(line, _blank(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Library call with incorrectly specified arguments: memset value/length transposed, a printf-family format whose conversions do not match the arguments, or open() with O_CREAT and no mode",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
