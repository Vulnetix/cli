# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_685

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-685",
	"name": "Function Call With Incorrect Number of Arguments",
	"description": "A C or C++ variadic call passes a different number of arguments than its format asks for, or omits an argument a flag makes mandatory. Reported: printf, fprintf, sprintf, snprintf, dprintf, asprintf, syslog, the BSD err/errx/warn/warnx (and the wide forms) with a literal format, on one line or continued over up to three following lines, whose conversions (counting * width and precision) differ from the arguments that follow, so the call reads stack values that were never passed (a disclosure, or a crash on %s) or drops one; scanf, fscanf and sscanf whose conversions (not counting %* suppressed ones, counting %[...] sets and %n) differ from the pointers passed, so a conversion writes through a garbage pointer; and open()/openat() with O_CREAT or O_TMPFILE but no mode argument, so the new file's permissions come from an indeterminate register. Not reported: calls that stay open beyond three continuation lines, formats built from macros (PRIu64) or using positional %n$ conversions, project wrapper functions, open() with a mode or without O_CREAT, comments and string literals. VNX-628 also reports the printf and open() shapes.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-685/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [685],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["function-arguments", "cwe-685"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_pre := `(?:^|[^\w.>])(?:std::)?`

_lit := `\s*L?"((?:\\.|[^"\\])*)"(.*)$`

_one := `\s*[^,"()]+(?:\([^()]*\))?\s*,`

_printf_res := [
	concat("", [_pre, `(?:printf|wprintf|warnx|warn)\s*\(`, _lit]),
	concat("", [_pre, `(?:fprintf|sprintf|dprintf|syslog|fwprintf|asprintf|errx|err)\s*\(`, _one, _lit]),
	concat("", [_pre, `(?:snprintf|swprintf)\s*\(`, _one, _one, _lit]),
]

_scanf_res := [
	concat("", [_pre, `(?:scanf|wscanf)\s*\(`, _lit]),
	concat("", [_pre, `(?:fscanf|sscanf|fwscanf|swscanf)\s*\(`, _one, _lit]),
]

_pspec := `%[-+ #0']*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|L|z|j|t|q|I64|I32)?[diouxXeEfFgGaAcspnCS]`

_sspec := `%(\*)?\d*(?:hh|h|ll|l|L|z|j|t|q|m)?(?:[diouxXaAeEfFgGcspnCS]|\[\^?\]?[^\]]*\])`

_printf_need(fmt) := n if {
	f := replace(fmt, "%%", "")
	not regex.match(`%\d+\$`, f)
	specs := regex.find_all_string_submatch_n(_pspec, f, -1)
	stars := count([1 | some s in specs; s[1] == "*"]) + count([1 | some s in specs; s[2] == "*"])
	count(indexof_n(f, "%")) == count(specs) + count(indexof_n(f, "%m"))
	n := count(specs) + stars
}

_scanf_need(fmt) := n if {
	f := replace(fmt, "%%", "")
	not regex.match(`%\d+\$`, f)
	specs := regex.find_all_string_submatch_n(_sspec, f, -1)
	count(indexof_n(f, "%")) == count(specs)
	n := count([1 | some s in specs; s[1] != "*"])
}

_strip_nested(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "_"), `\([^()]*\)`, "_"), `\([^()]*\)`, "_")

# Arguments after the format, up to the call's closing parenthesis.
_given(rest) := n if {
	r := _strip_nested(regex.replace(_blank(rest), `\{[^{}]*\}`, "_"))
	m := regex.find_all_string_submatch_n(`^\s*(?:,([^()]*))?\)`, r, 1)
	count(m) > 0
	n := _count_args(m[0][1])
}

_count_args(a) := 0 if trim_space(a) == ""

_count_args(a) := count(split(a, ",")) if trim_space(a) != ""

_bad(line, _) if {
	regex.match(`printf|syslog|err|warn`, line)
	some re in _printf_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	_printf_need(m[0][1]) != _given(m[0][2])
}

_bad(line, _) if {
	contains(line, "scanf")
	some re in _scanf_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	_scanf_need(m[0][1]) != _given(m[0][2])
}

_bad(_, code) if {
	regex.match(`O_(?:CREAT|TMPFILE)`, code)
	regex.match(`(^|[^\w.>])open\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*[^,()]*\bO_(CREAT|TMPFILE)\b[^,()]*\)`, code)
}

_bad(_, code) if {
	regex.match(`O_(?:CREAT|TMPFILE)`, code)
	regex.match(`(^|[^\w.>])openat\s*\(\s*[^,()]+,\s*[^,()]+(?:\([^()]*\))?\s*,\s*[^,()]*\bO_(CREAT|TMPFILE)\b[^,()]*\)`, code)
}

# A call left open on its line continues on up to three following lines.
_call_text(_, _, line, code) := line if count(indexof_n(code, "(")) <= count(indexof_n(code, ")"))

_call_text(lines, i, line, code) := concat(" ", array.concat([line], array.slice(lines, i + 1, i + 4))) if {
	count(indexof_n(code, "(")) > count(indexof_n(code, ")"))
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`printf|scanf|syslog|err|warn|O_CREAT|O_TMPFILE`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`printf|scanf|syslog|err|warn|O_CREAT|O_TMPFILE`, line)
	not helpers.is_comment_line(line)
	code := _blank(line)
	regex.match(`printf\s*\(|scanf\s*\(|syslog\s*\(|(?:^|[^\w.>])(?:errx?|warnx?)\s*\(|O_CREAT|O_TMPFILE`, code)
	text := _call_text(lines, i, line, code)
	_bad(text, _blank(text))
	finding := {
		"rule_id": metadata.id,
		"message": "Call passes the wrong number of arguments: a printf/scanf-family format whose conversions do not match the arguments, or open() with O_CREAT and no mode",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
