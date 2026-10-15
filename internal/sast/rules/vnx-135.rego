# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_135

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-135",
	"name": "Incorrect Calculation of Multi-Byte String Length",
	"description": "Reports C/C++ code that mixes up wide-character counts and byte counts: (1) malloc/xmalloc/alloca/realloc sized by wcslen() with no sizeof (and no * 2 / * 4), which allocates one byte per wide character, or too few bytes for a wcstombs() conversion; (2) memcpy/memmove/memcmp/memset given a wcslen() count with no sizeof, which copies only part of the string; (3) a function that counts in wide characters (wcsncpy, wcsncat, wcslcpy, wcslcat, wmemcpy, wmemmove, wmemset, swprintf, vswprintf, _snwprintf, mbstowcs, fgetws, wcsftime, wcsxfrm, MultiByteToWideChar, GetWindowTextW, GetModuleFileNameW, GetCurrentDirectoryW) given sizeof(buf) as its character-count argument (also when the call spans lines; a sizeof in another argument, such as the byte count MultiByteToWideChar takes for its input, is not reported), a byte count that is two or four times the buffer's length in characters, so the call writes past the buffer; (4) strlen() on a variable declared wchar_t/WCHAR in the 40 lines above, usually through a (char *) cast, which stops at the first zero byte of a wide character. Not reported: sizes multiplied by sizeof(wchar_t) or sizeof(*p), counts written sizeof(buf)/sizeof(buf[0]), ARRAY_SIZE() or _countof(), new wchar_t[wcslen(s) + 1] (an element count), narrow strings, comments. UTF-8 length mistakes in other languages are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-135/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [135],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["multibyte", "unicode", "wchar", "cwe-135"],
}

_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

_is_c(path) if {
	some ext in _exts
	endswith(path, ext)
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

_wide_file(content) if {
	some lit in {"wcs", "wchar_t", "WCHAR", "wmem", "wprintf", "fgetws", "MultiByteToWideChar", "TextW(", "NameW(", "DirectoryW("}
	contains(content, lit)
}

_wide_lines := {path: split(content, "\n") |
	some path, content in input.file_contents
	_is_c(path)
	_wide_file(content)
}

_no_char_size(expr) if {
	not contains(expr, "sizeof")
	not regex.match(`\*\s*[24]\b|\b[24]\s*\*`, expr)
}

# (1) allocation sized by wcslen() in characters
_alloc_size(line) := m[1] if {
	m := regex.find_all_string_submatch_n(`\b(?:x?malloc|alloca)\s*\((.*)\)`, line, 1)[0]
}

_alloc_size(line) := m[1] if {
	m := regex.find_all_string_submatch_n(`\bx?realloc\s*\([^,]+,(.*)\)`, line, 1)[0]
}

findings contains f if {
	some path, lines in _wide_lines
	some i, line in lines
	contains(line, "wcslen")
	contains(line, "alloc")
	not helpers.is_comment_line(line)
	s := _alloc_size(line)
	regex.match(`\bwcslen\s*\(`, s)
	_no_char_size(s)
	f := _finding(path, i, line, "Allocation sized by wcslen(), which counts wide characters, not bytes: the buffer is too small by a factor of sizeof(wchar_t) (or by MB_CUR_MAX for a wcstombs() result); multiply by sizeof(wchar_t)")
}

# (2) memcpy & co given a wcslen() count
findings contains f if {
	some path, lines in _wide_lines
	some i, line in lines
	contains(line, "wcslen")
	contains(line, "mem")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b(memcpy|memmove|memcmp|memset)\s*\((.*\bwcslen\s*\(.*)\)`, line, 1)[0]
	_no_char_size(m[2])
	f := _finding(path, i, line, sprintf("%s() takes a byte count but is given wcslen(), a count of wide characters: only part of the string is copied or compared; multiply by sizeof(wchar_t) or use wmem*()", [m[1]]))
}

# (3) wide-count API given a byte count
_wide_fn := `\b(wcsncpy|wcsncat|wcslcpy|wcslcat|wcsncpy_s|wmemcpy|wmemmove|wmemset|swprintf|vswprintf|_snwprintf|snwprintf|mbstowcs|fgetws|wcsftime|wcsxfrm|MultiByteToWideChar|GetWindowTextW|GetModuleFileNameW|GetCurrentDirectoryW)\s*\(`

# 1-based position of each function's character-count argument.
_count_pos := {
	"wcsncpy": 3, "wcsncat": 3, "wcslcpy": 3, "wcslcat": 3, "wcsncpy_s": 2,
	"wmemcpy": 3, "wmemmove": 3, "wmemset": 3, "swprintf": 2, "vswprintf": 2,
	"_snwprintf": 2, "snwprintf": 2, "mbstowcs": 3, "fgetws": 2, "wcsftime": 2,
	"wcsxfrm": 3, "MultiByteToWideChar": 6, "GetWindowTextW": 3,
	"GetModuleFileNameW": 3, "GetCurrentDirectoryW": 1,
}

# One call argument: string literals and up to two levels of parentheses.
_arg := `(?:"[^"]*"|'[^']*'|[^,()"']|\((?:[^()]|\([^()]*\))*\))*`

# The call's text: the line, joined with the next two when the call breaks.
_wcall_text(lines, i) := lines[i] if contains(lines[i], ";")

_wcall_text(lines, i) := concat(" ", array.slice(lines, i, min([count(lines), i + 3]))) if not contains(lines[i], ";")

findings contains f if {
	some path, lines in _wide_lines
	some i, line in lines
	not helpers.is_comment_line(line)
	fm := regex.find_all_string_submatch_n(_wide_fn, line, 1)[0]
	fn := fm[1]
	text := _wcall_text(lines, i)
	contains(text, "sizeof")
	pos := _count_pos[fn]
	prefix := concat("", [`\b`, fn, `\s*\(\s*`, concat("", [x | some _ in numbers.range(1, pos - 1); x := concat("", [_arg, `,\s*`])])])
	m := regex.find_all_string_submatch_n(concat("", [prefix, `(?:\(\s*\w+\s*\)\s*)?sizeof\s*(\(\s*[A-Za-z_][\w\.>-]*\s*\)|[A-Za-z_]\w*)\s*(?:-\s*\d+\s*)?[,)]`]), text, 1)[0]
	not regex.match(`(?i)^\(?\s*(wchar_t|wchar|tchar|wint_t)\s*\)?$`, m[1])
	f := _finding(path, i, line, sprintf("%s() counts in wide characters but is given sizeof%s, a byte count two to four times the length in characters: the call can write past the buffer; pass sizeof(buf) / sizeof(buf[0]) or _countof(buf)", [fn, m[1]]))
}

# (4) strlen() on a wide string
findings contains f if {
	some path, lines in _wide_lines
	some i, line in lines
	contains(line, "strlen")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bstrlen\s*\(\s*(?:\(\s*(?:const\s+)?(?:unsigned\s+)?char\s*(?:const\s*)?\*\s*\)\s*)?([A-Za-z_]\w*)\s*\)`, line, 1)[0]
	v := m[1]
	some k in numbers.range(max([0, i - 40]), i)
	regex.match(concat("", [`\b(?:wchar_t|WCHAR|wint_t)\s*(?:const\s*)?(?:\*\s*(?:const\s*)?)?`, v, `\b\s*(?:\[|=|;|,|\))`]), lines[k])
	f := _finding(path, i, line, sprintf("strlen() on %s, which is a wide-character string: it counts bytes up to the first zero byte of a wide character, not characters; use wcslen()", [v]))
}
