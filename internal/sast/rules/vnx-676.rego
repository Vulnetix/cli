# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_676

import rego.v1

metadata := {
	"id": "VNX-676",
	"name": "Use of Potentially Dangerous Function",
	"description": "C and C++ calls to the classic unbounded string functions, in the forms that can actually overflow their destination: gets() and _getws() (always); strcpy, stpcpy, strcat, wcscpy and wcscat (also std::-qualified) when the source is not a string literal, an upper-case macro constant or a choice between literals, and its length was not measured (strlen/wcslen/strnlen of it) nor the destination's sizeof compared in an if/assert in the 15 lines above; sprintf whose literal format has a %s/%ls conversion with no precision, and vsprintf; scanf, fscanf, sscanf, vscanf, vfscanf, vsscanf and the wide forms whose literal format has a %s, %ls or %[ conversion with no field width. Calls that wrap over several lines are read across them; a format made of adjacent literals (with inttypes.h macros such as PRIu64 between them) is read as one, and literals of later arguments or lines are not part of it. Not reported: the bounded APIs (fgets, strncpy, strlcpy, strncat, snprintf, vsnprintf, the _s functions), %.Ns, %Ns, %*s and %ms conversions, sprintf with only numeric conversions or a non-literal format (a format-string issue, not this one), prototypes, #define lines, methods and other functions whose names merely contain these (b.strcpy, p->gets, my_strcpy, fgets), comments and string literals. VNX-C-001 reports the same unbounded copies with a wider set of Windows variants, and VNX-242 reports gets().",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-676/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [676],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["dangerous-function", "cwe-676", "buffer-overflow"],
}

_c_exts := [".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"]

_names := `gets|_getws|strcpy|stpcpy|strcat|wcscpy|wcscat|sprintf|vsprintf|scanf|fscanf|sscanf|vscanf|vfscanf|vsscanf|wscanf|fwscanf|swscanf`

_word_re := concat("", [`\b(?:`, _names, `)\s*\(`])

_call_re := concat("", [`^(.*?)(?:\bstd::)?\b(`, _names, `)\s*\((.*)$`])

_gets := {"gets", "_getws"}

_copy := {"strcpy", "stpcpy", "strcat", "wcscpy", "wcscat"}

# argument index of the format literal
_fmt_arg("sprintf") := 1

_fmt_arg(fn) := 0 if fn in {"scanf", "vscanf", "wscanf"}

_fmt_arg(fn) := 1 if fn in {"fscanf", "sscanf", "vfscanf", "vsscanf", "fwscanf", "swscanf"}

_mask_chars(s) := regex.replace(s, `'(?:[^'\\]|\\.)'`, "'_'")

_mask_strings(s) := regex.replace(_mask_chars(s), `"(?:[^"\\]|\\.)*"`, `""`)

_mask(s) := regex.replace(regex.replace(_mask_strings(s), `/\*.*?\*/`, " "), `(?://|/\*).*$`, "")

# Raw text with comments removed (literals kept), for reading formats.
_uncomment(s) := regex.replace(regex.replace(s, `/\*.*?\*/`, " "), `//[^"]*$`, "")

_nows(s) := regex.replace(s, `\s+`, "")

_comment_line(l) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, l)

_in_block_comment(lines, i) if {
	start := max([0, i - 40])
	i > start
	marks := [j | some j in numbers.range(start, i - 1); _comment_mark(lines[j])]
	count(marks) > 0
	l := _mask_strings(lines[max(marks)])
	contains(l, "/*")
	not contains(substring(l, indexof(l, "/*"), -1), "*/")
}

_comment_mark(l) if contains(l, "/*")

_comment_mark(l) if contains(l, "*/")

# What precedes the name is not a type (prototype), `.`/`->` (a method) or a word.
_call_prefix_ok(pre) if {
	t := trim_right(pre, " \t")
	not regex.match(`(?:\.|->|[\w*&])$`, t)
}

_call_prefix_ok(pre) if regex.match(`(?:^|[^\w])(?:return|else|do|case)\s*$`, pre)

_call_text(lines, i, rest) := concat(" ", array.concat([rest], [_mask(lines[k]) |
	some k in numbers.range(i + 1, i + 3)
	k < count(lines)
]))

_raw_text(lines, i, rest) := concat(" ", array.concat([rest], [_uncomment(lines[k]) |
	some k in numbers.range(i + 1, i + 3)
	k < count(lines)
]))

_flat(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "0"), `\([^()]*\)`, "0"), `\([^()]*\)`, "0")

_inner(f) := substring(f, 0, indexof(f, ")")) if indexof(f, ")") >= 0

_inner(f) := f if indexof(f, ")") < 0

_args(call) := [trim_space(a) | some a in split(_inner(_flat(call)), ",")]

_constant(src) if regex.match(`^\s*(?:(?:L|u8|u|U)?""|[A-Z][A-Z0-9_]*|\s)+$`, src)

_constant(src) if regex.match(`^[^?]*\?\s*(?:L|u8|u|U)?""\s*:\s*(?:L|u8|u|U)?""\s*$`, src)

_measured(lines, i, dst, src) if {
	s := _nows(src)
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := _nows(_mask(lines[j]))
	some f in ["strlen(", "wcslen(", "strnlen("]
	contains(l, concat("", [f, s]))
}

_measured(lines, i, dst, _) if {
	d := _nows(dst)
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := _nows(_mask(lines[j]))
	regex.match(`(?:^|[^\w])(?:if|while|assert)\(`, l)
	some f in ["sizeof(", "sizeof"]
	contains(l, concat("", [f, d]))
}

# The format literal. Adjacent literals (with inttypes.h macros such as
# PRIu64 between them) are one argument; the format is the run of literals
# that belongs to argument idx, counting one run for every earlier argument
# that is itself a literal. Literals of later arguments or later lines are
# never part of it.
_run_re := `(?:L|u8|u|U)?"(?:[^"\\]|\\.)*"(?:\s*(?:[A-Z][A-Za-z0-9_]*\s*)?(?:L|u8|u|U)?"(?:[^"\\]|\\.)*")*`

_format(lines, i, rest_raw, args, idx) := fmt if {
	count(args) > idx
	regex.match(`^(?:\s*(?:L|u8|u|U)?""|\s*[A-Z][A-Za-z0-9_]*)+\s*$`, args[idx])
	contains(args[idx], `""`)
	raw := _raw_text(lines, i, rest_raw)
	skip := count([k | some k in numbers.range(0, idx - 1); idx > 0; contains(args[k], `""`)])
	runs := regex.find_all_string_submatch_n(_run_re, raw, -1)
	count(runs) > skip
	fmt := concat("", [l[1] | some l in regex.find_all_string_submatch_n(`"((?:[^"\\]|\\.)*)"`, runs[skip][0], -1)])
}

_unbounded_printf(fmt) if regex.match(`%[-+ #0]*\d*l?s`, regex.replace(fmt, `%%`, ""))

_unbounded_scanf(fmt) if regex.match(`%l?(?:s|\[)`, regex.replace(fmt, `%%`, ""))

_hit(_, _, fn, _, _) := "reads a line of unlimited length into a fixed buffer; use fgets(buf, sizeof buf, stdin)" if fn in _gets

_hit(lines, i, fn, call, _) := "copies a source of unknown length without a destination size; use strlcpy/strlcat or snprintf with sizeof(dst)" if {
	fn in _copy
	args := _args(call)
	count(args) >= 2
	not _constant(args[1])
	not _measured(lines, i, args[0], args[1])
}

_hit(_, _, "vsprintf", _, _) := "formats without a destination size; use vsnprintf(buf, sizeof buf, ...)"

_hit(lines, i, "sprintf", call, raw) := "formats a %s without precision into a buffer of fixed size; use snprintf(buf, sizeof buf, ...)" if {
	fmt := _format(lines, i, raw, _args(call), 1)
	_unbounded_printf(fmt)
}

_hit(lines, i, fn, call, raw) := "reads a %s/%[ conversion with no field width into a fixed buffer; give the width (%31s) or use %ms" if {
	idx := _fmt_arg(fn)
	fn != "sprintf"
	fmt := _format(lines, i, raw, _args(call), idx)
	_unbounded_scanf(fmt)
}

_file_cand(c) if {
	some n in ["gets", "_getws", "strcpy", "stpcpy", "strcat", "wcscpy", "wcscat", "sprintf", "scanf"]
	contains(c, n)
}

_cand(line) if contains(line, "gets")

_cand(line) if contains(line, "cpy")

_cand(line) if contains(line, "cat")

_cand(line) if contains(line, "printf")

_cand(line) if contains(line, "scanf")

findings contains finding if {
	some path, content in input.file_contents
	some ext in _c_exts
	endswith(path, ext)
	_file_cand(content)
	regex.match(_word_re, content)
	lines := split(content, "\n")
	some i, line in lines
	_cand(line)
	regex.match(_word_re, line)
	not _comment_line(line)
	masked := _mask(line)
	m := regex.find_all_string_submatch_n(_call_re, masked, 1)
	_call_prefix_ok(m[0][1])
	fn := m[0][2]
	call := _call_text(lines, i, m[0][3])
	rm := regex.find_all_string_submatch_n(concat("", [`\b`, fn, `\s*\((.*)$`]), _uncomment(line), 1)
	msg := _hit(lines, i, fn, call, rm[0][1])
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() %s", [fn, msg]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
