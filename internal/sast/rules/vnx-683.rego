# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_683

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-683",
	"name": "Function Call With Incorrect Order of Arguments",
	"description": "A C or C++ library call whose arguments are visibly in the wrong order. Reported: memset()/wmemset() with the fill value and the length transposed (a literal 0 or '\\0' length after a non-zero value, so nothing is cleared); memcpy, memmove, strcpy, strncpy, strcat, strncat, strlcpy, stpcpy, wcscpy and wmemcpy whose first (destination) argument is named like a source (src, source, from, input, in, orig, with an optional _buf/_ptr/_str/_data suffix) and whose second argument is named like a destination (dst, dest, destination, to, target, out, output), so the copy runs backwards; and fputs, fputc, putc, fwrite, fread and fgets called with the stream (stdout, stderr, stdin, fp, fh, stream, or a name declared FILE * in the 40 lines above with no other declaration of it in view) as the first argument instead of the last. Not reported: correctly ordered calls, memset(p, 0, 0), copies where only one argument has a telling name, calls in comments or string literals, and files of other languages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-683/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [683],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["function-call-wrong-argument-order", "cwe-683"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_memset_re := `(?:^|[^\w.>])(?:std::)?(?:memset|wmemset)\s*\(\s*[^,]+,\s*([^,]+?)\s*,\s*(?:0|0x0|0L|0U|0UL|'')\s*\)`

_bad(code) if {
	contains(code, "memset")
	m := regex.find_all_string_submatch_n(_memset_re, code, 1)
	count(m) > 0
	not regex.match(`^(0|0x0+|''|NULL|\(char\)\s*0)$`, m[0][1])
}

_copy_re := `(?:^|[^\w.>])(?:std::)?(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|strlcpy|stpcpy|wcscpy|wmemcpy)\s*\(\s*&?\s*(?:\w+(?:\.|->))*(\w+)\s*,\s*&?\s*(?:\w+(?:\.|->))*(\w+)\s*[,)]`

_suffix := `(?:_?(?:buf|buffer|ptr|str|data))?$`

_bad(code) if {
	regex.match(`cpy|cat|memmove`, code)
	m := regex.find_all_string_submatch_n(_copy_re, code, 1)
	count(m) > 0
	regex.match(concat("", [`(?i)^(?:src|source|from|input|in|orig|original)`, _suffix]), m[0][1])
	regex.match(concat("", [`(?i)^(?:dst|dest|destination|to|target|output|out)`, _suffix]), m[0][2])
}

_bad(code) if {
	regex.match(`(?:^|[^\w.>])(?:std::)?(?:fputs|fputws|fputc|putc|fwrite|fread|fgets)\s*\(\s*(?:stdout|stderr|stdin|fp|fh|stream|outfp|infp|out_fp|in_fp|logfp)\s*,`, code)
}

# The first argument is a name the file declares as FILE *.
# The first argument is a name declared as FILE * in the 40 lines above, and
# every declaration of that name in view is a FILE * (a local `sds out` beside
# a FILE *out elsewhere in the file is not a stream).
_not_types := {"return", "else", "goto", "case", "sizeof", "FILE", "const", "static", "delete"}

_bad_declared_stream(code, lines, i) if {
	some g in regex.find_all_string_submatch_n(`(?:^|[^\w.>])(?:std::)?(?:fputs|fputws|fputc|putc|fwrite|fread|fgets)\s*\(\s*(\w+)\s*,`, code, 1)
	v := g[1]
	win := helpers.code_window(lines, i, 40, 0)
	regex.match(concat("", [`\bFILE\s*\*\s*`, v, `\s*[;=,)]`]), win)
	others := [t |
		some d in regex.find_all_string_submatch_n(concat("", [`(?m)(?:^|[(,;{])\s*(?:(?:const|static|struct|unsigned)\s+)*([A-Za-z_]\w*)(?:\s+|\s*\*+\s*)`, v, `\s*[;=,)\[]`]), win, -1)
		t := d[1]
		not t in _not_types
	]
	count(others) == 0
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "FILE")
	regex.match(`fputs|fputws|fputc|putc|fwrite|fread|fgets`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`fputs|fputws|fputc|putc|fwrite|fread|fgets`, line)
	not helpers.is_comment_line(line)
	code := _blank(line)
	not _bad(code)
	_bad_declared_stream(code, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Arguments are in the wrong order: a FILE * stream is passed first. Swap them to match the function's signature",
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
	regex.match(`memset|cpy|cat\s*\(|memmove|fputs|fputws|fputc|putc|fwrite|fread|fgets`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`memset|cpy|cat\s*\(|memmove|fputs|fputws|fputc|putc|fwrite|fread|fgets`, line)
	not helpers.is_comment_line(line)
	_bad(_blank(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Arguments are in the wrong order: memset value and length transposed, a copy whose destination is the source, or a stream passed first. Swap them to match the function's signature",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
