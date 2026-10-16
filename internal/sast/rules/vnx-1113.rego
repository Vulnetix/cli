# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1113

import rego.v1

metadata := {
	"id": "VNX-1113",
	"name": "Inappropriate Comment Style",
	"description": "A '/* ... */' block comment opened inside another block comment, in a language where block comments do not nest (C, C++, Java, JavaScript/TypeScript, Go, C#, PHP). The first '*/' closes both, so text the author believed was commented out (typically code disabled by wrapping it, inner comment and all, in '/* ... */') is compiled, and the outer '*/' is left stray. Reported at the nested '/*' line. Not reported: block comments that close before the next one opens, '/*' in the middle of a line (globs such as 'a/*.c', strings), Rust, Swift, Kotlin and Scala, whose block comments nest legally, and openers more than 50 lines apart.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1113/",
	"languages": ["c", "cpp", "java", "javascript", "go", "csharp", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1113],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["comments", "inappropriate-comment", "nested-comment", "cwe-1113"],
}

_ext(path) if regex.match(`\.(c|h|cc|cpp|cxx|hpp|hh|java|js|jsx|mjs|cjs|ts|tsx|mts|cts|go|cs|php)$`, path)

_window := 50

# Comment delimiters are located by byte offset (openers as 2*o, closers as
# 2*c+1) and sorted, so two openers with no closer between them are adjacent.
_events(content) := sort(array.concat(
	[x | some o in indexof_n(content, "/*"); x := 2 * o],
	[x | some c in indexof_n(content, "*/"); x := (2 * c) + 1],
))

# the delimiter at offset o is the first thing on its line
_line_start(content, o) if {
	s := max([0, o - 200])
	regex.match(`(?:^|\n)[ \t]*$`, substring(content, s, o - s))
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	contains(content, "/*")
	# whole-file gate: a line-start opener, text without "*/", then a line-start opener
	regex.match(`/\*(?:[^*]|\*+[^*/])*\n[^\n]*/\*`, content)
	ev := _events(content)
	some p, e in ev
	p > 0
	e % 2 == 0
	prev := ev[p - 1]
	prev % 2 == 0
	outer := prev / 2
	inner := e / 2
	inner > outer + 1
	_inner_opener(content, inner)
	_line_start(content, outer)
	span := count(indexof_n(substring(content, outer, inner - outer), "\n"))
	span >= 1
	span <= _window
	idx := count(indexof_n(substring(content, 0, inner), "\n"))
	line := split(content, "\n")[idx]
	finding := {
		"rule_id": metadata.id,
		"message": "Block comment opened inside another block comment; block comments do not nest, so its '*/' ends the outer comment and the text after it is compiled",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": idx + 1,
		"snippet": line,
	}
}

_inner_opener(content, o) if _line_start(content, o)

# a trailing comment on a commented-out code line: 'x = 1;   /* note */'
_inner_opener(content, o) if {
	s := max([0, o - 200])
	before := substring(content, s, o - s)
	m := regex.find_all_string_submatch_n(`(?:^|\n)([^\n]*\S[ \t]+)$`, before, 1)
	count(m) > 0
	count(indexof_n(m[0][1], `"`)) % 2 == 0
	count(indexof_n(m[0][1], "`")) == 0
	regex.match(`^/\*[ \t*][^\n]*\*/`, substring(content, o, 200))
}
