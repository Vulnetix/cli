# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1056

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1056",
	"name": "Invokable Control Element with Variadic Parameters",
	"description": "A C or C++ function is defined with a C-style variadic parameter list whose last named parameter is a format string (a char, gchar, wchar_t or TCHAR pointer named fmt, format, msg or message, such as void log_event(int level, const char *fmt, ...)), its body hands the va_list to the v*printf or v*scanf family (vfprintf, vsnprintf, g_strdup_vprintf, vsscanf, vsyslog, ...), and neither the definition nor any prototype of the same function in the scanned sources carries a format attribute (__attribute__((format(printf|scanf, n, m))), __printf(n, m), __printflike, G_GNUC_PRINTF, or any PRINTF-named macro given two argument positions such as PRINTF_FMT(1, 2)). The variadic arguments are then unchecked: the compiler cannot match them to the format string, so a missing, extra or wrongly typed argument is undefined behaviour read off the stack (CWE-1056, and the route to CWE-134). The parameter list may span several lines and C++ member definitions (Logger::log) are covered. Not reported: prototypes, macros (#define F(fmt, ...)), function pointers, variadic templates (typename... Args, which are type-checked), variadic functions whose last named parameter is a count or a sentinel-terminated pointer (nothing an attribute could check), wrappers that are attributed in a header, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1056/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1056],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["variadic-params", "format-string", "cwe-1056"],
}

_src_exts := {".c", ".cc", ".cpp", ".cxx", ".c++"}

_all_exts := {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx"}

_has_ext(path, exts) if {
	some ext in exts
	endswith(path, ext)
}

# The variadic tail: the last named parameter is a char pointer format string.
_tail_re := `(?i)\b(?:g?char|wchar_t|tchar)\s*(?:const\s*)?\*\s*(?:const\s+)?(?:\w*fmt\w*|\w*format\w*|msg|message)\s*,\s*\.\.\.\s*\)`

# A function definition head on one line: return type, name, parameter list.
_one_line_re := `^(?:\s*[A-Za-z_][\w\s\*&:<>,]*?[\s\*&])?([A-Za-z_][\w:~]*)\s*\(([^;{}()]*)\)\s*(?:const\s*)?(?:\{.*)?$`

# Start of a parameter list continued on later lines.
_open_re := `^(?:\s*[A-Za-z_][\w\s\*&:<>,]*?[\s\*&])?([A-Za-z_][\w:~]*)\s*\(([^;{}()]*)$`

_short_name(name) := n if {
	parts := split(name, "::")
	n := parts[count(parts) - 1]
}

# The line ends a definition head: its body opens here or on the next code line.
_opens_body(lines, j) if regex.match(`\)\s*(?:const\s*)?\{`, lines[j])

_opens_body(lines, j) if {
	k := helpers.next_code_index(lines, j, 2)
	startswith(trim_space(lines[k]), "{")
}

# Candidate definitions: [line index of the head, function name].
_defs(lines) := _defs_single(lines) | _defs_multi(lines)

_defs_single(lines) := {[i, name] |
	some i, line in lines
	contains(line, "...")
	regex.match(_tail_re, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*#`, line)
	m := regex.find_all_string_submatch_n(_one_line_re, line, 1)
	count(m) > 0
	not regex.match(`^(?:if|for|while|switch|return|sizeof)$`, m[0][1])
	_opens_body(lines, i)
	name := m[0][1]
}

_defs_multi(lines) := {[s, name] |
	some i, line in lines
	i > 0
	contains(line, "...")
	regex.match(`\.\.\.\s*\)`, line)
	not helpers.is_comment_line(line)
	not contains(line, "(")
	some s in numbers.range(max([0, i - 3]), i - 1)
	m := regex.find_all_string_submatch_n(_open_re, lines[s], 1)
	count(m) > 0
	regex.match(_tail_re, concat(" ", [lines[k] | some k in numbers.range(s, i)]))
	not regex.match(`^(?:if|for|while|switch|return|sizeof)$`, m[0][1])
	not regex.match(`^\s*#`, lines[s])
	_opens_body(lines, i)
	name := m[0][1]
}

# The body hands its va_list to the printf family, so the format string really
# is a printf format (a custom format such as "%S" or "sc!" cannot take the
# attribute). Bounded to the first 40 lines of the body.
_forwards_to_vprintf(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 40]))
	regex.match(`(?:\b|_)(?:std::)?v(?:f|sn|s|as|d)?w?printf\w*\s*\(|(?:\b|_)v(?:f|s)?w?scanf(?:_s)?\s*\(|\bvsyslog\s*\(|\bvwarnx?\s*\(|\bverrx?\s*\(`, lines[k])
	not helpers.is_comment_line(lines[k])
}

_attr_re := `(?i)format\s*\(\s*(?:__)?(?:gnu_|ms_)?(?:printf|scanf)|printflike|scanflike|printf_like|_printf\s*\(|gnuc_printf|gnuc_scanf|printf_format|attribute_printf|format_printf|_Printf_format_string_|_Scanf_format_string_|\b\w*(?:printf|scanf)\w*\s*\(\s*\d+\s*,\s*\d+\s*\)`

# A printf-style attribute next to a declaration or definition of the name, in
# any C/C++ file of the scan: on the line before, or after the parameter list
# on the same line or the two lines that follow.
_attributed(short) if {
	some p, c in input.file_contents
	_has_ext(p, _all_exts)
	contains(c, short)
	ls := split(c, "\n")
	some j, l in ls
	contains(l, short)
	regex.match(concat("", [`\b`, short, `\s*\(`]), l)
	_attr_near(ls, j)
}

_attr_near(ls, j) if {
	j > 0
	regex.match(_attr_re, ls[j - 1])
}

_attr_near(ls, j) if {
	parts := split(ls[j], "...")
	count(parts) > 1
	regex.match(_attr_re, parts[count(parts) - 1])
}

# On the two lines that follow, while the declaration has not ended: an
# attribute on the next prototype does not belong to this one.
_attr_near(ls, j) if {
	j + 1 <= count(ls) - 1
	some k in numbers.range(j + 1, min([count(ls) - 1, j + 2]))
	regex.match(_attr_re, ls[k])
	every m in numbers.range(j, k - 1) {
		not regex.match(`[;{]\s*$`, ls[m])
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path, _src_exts)
	contains(content, "...")
	regex.match(_tail_re, content)
	lines := split(content, "\n")
	some d in _defs(lines)
	_forwards_to_vprintf(lines, d[0])
	short := _short_name(d[1])
	not _attributed(short)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s takes a format string and C variadic arguments that the compiler cannot check; add __attribute__((format(printf, n, m))) to its prototype or use a type-checked interface (CWE-1056)", [short]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d[0] + 1,
		"snippet": lines[d[0]],
	}
}
