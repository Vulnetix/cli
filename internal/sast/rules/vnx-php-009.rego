package vulnetix.rules.vnx_php_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-009",
	"name": "PHP preg_replace with /e modifier",
	"description": "preg_replace() or preg_filter() is called with a pattern that carries the e (PREG_REPLACE_EVAL) modifier, which evaluates the replacement string as PHP code after substitution, so text matched from the subject becomes code (remote code execution when the subject is user-controlled). The pattern is recognised as a string literal whose closing delimiter (any delimiter, including bracket pairs such as {}) is followed only by valid PCRE modifiers including e: given inline, on the next lines of a call broken across lines, in an array of patterns, or through a variable assigned such a literal within the 15 lines above. The modifier was deprecated in PHP 5.5 and removed in PHP 7.0. Not reported: preg_replace_callback(), patterns without e, a pattern built at run time from non-literal parts (unless its last concatenated literal is the closing delimiter and modifiers including e, such as . ')/ei'), lookalike functions such as my_preg_replace(), the call text inside a comment or a string literal, and an /e pattern quoted only in a trailing // or # comment after a safe call. mb_ereg_replace() with the e option is covered by VNX-PHP-024.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-009/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["rce", "code-injection", "deprecated", "php"],
}

_call_re := `\bpreg_(?:replace|filter)\s*\(`

_lit_re := `'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"`

_close := {"(": ")", "{": "}", "[": "]", "<": ">"}

_closing(d) := c if c := _close[d]

_closing(d) := d if not _close[d]

# _e_pattern: the body of a string literal is a PCRE pattern whose modifiers
# include e. The delimiter is the first character (not alphanumeric, not a
# backslash, not whitespace); the modifiers are what follows its last closing
# occurrence, and must all be valid modifier letters.
_e_pattern(body) if {
	d := substring(body, 0, 1)
	regex.match(`^[^A-Za-z0-9\\\s]$`, d)
	c := _closing(d)
	idxs := indexof_n(body, c)
	last := max(idxs)
	last > 0
	mods := substring(body, last + 1, -1)
	regex.match(`^[imsxuADSUXJe]*e[imsxuADSUXJe]*$`, mods)
}

_literals(text) := [b |
	some m in regex.find_all_string_submatch_n(_lit_re, text, -1)
	b := concat("", [m[1], m[2]])
]

_has_e_literal(text) if {
	some b in _literals(text)
	_e_pattern(b)
}

# Code text of a line with every string literal emptied, so a call named
# inside a string is not a call.
_masked(line) := regex.replace(line, _lit_re, `''`)

# A line with any trailing // or # comment removed. String literals are
# stepped over so a // inside a pattern (or a #...# delimiter) is kept.
_strip_comment(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:[^'"/#]|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|/[^/*])*)(?://|#|/\*)`, line, 1)
	count(m) > 0
}

_strip_comment(line) := line if {
	not regex.match(`^(?:[^'"/#]|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|/[^/*])*(?://|#|/\*)`, line)
}

# The argument text after the call's opening parenthesis.
_after_call(line) := rest if {
	parts := regex.split(_call_re, _strip_comment(line))
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
}

# Inline (or the first argument begins on the call line).
_e_call(lines, i) if {
	rest := _after_call(lines[i])
	_has_e_literal(rest)
}

# The call is broken across lines: the arguments start on the next lines.
_e_call(lines, i) if {
	rest := _after_call(lines[i])
	regex.match(`^\s*(array\s*\(|\[)?\s*$`, rest)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	not helpers.is_comment_line(lines[k])
	_has_e_literal(_strip_comment(lines[k]))
}

# The pattern is a variable assigned an /e literal shortly above.
_e_call(lines, i) if {
	rest := _after_call(lines[i])
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*,`, rest, 1)
	v := m[0][1]
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(concat("", [`^\s*\$`, v, `\s*=[^=]`]), prev)
	_assignment_has_e(lines, j)
}

_assignment_has_e(lines, j) if _has_e_literal(_strip_comment(lines[j]))

# A pattern concatenated at run time whose final literal part supplies the
# closing delimiter and modifiers, e.g. "/(" . preg_quote($w) . ")/ei".
_assignment_has_e(lines, j) if regex.match(`\.\s*(?:'[^']*[/#~@!%|][imsxuADSUXJe]*e[imsxuADSUXJe]*'|"[^"]*[/#~@!%|][imsxuADSUXJe]*e[imsxuADSUXJe]*")\s*;`, _strip_comment(lines[j]))

# An array assignment spread over the following lines.
_assignment_has_e(lines, j) if {
	regex.match(`(array\s*\(|\[)\s*$`, lines[j])
	some k in numbers.range(j + 1, min([count(lines) - 1, j + 10]))
	not helpers.is_comment_line(lines[k])
	_has_e_literal(_strip_comment(lines[k]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "preg_")
	regex.match(_call_re, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_call_re, _masked(line))
	_e_call(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "preg_replace() with the /e modifier evaluates the replacement as PHP code; use preg_replace_callback() instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
