# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_563

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-563",
	"name": "Assignment to Variable without Use",
	"description": "A Python local variable is assigned a computed value that is overwritten before anything reads it (a dead store): inside a function, `name = <expression>` is followed, in the same block and at the same indentation, by another plain `name = ...` whose right-hand side does not read name, with no read of name, no continue/break and no end of the block in between. The first value is computed and thrown away, which usually means a check, a lookup or a signature verification that the code believes it performs is silently replaced (expected = hmac.new(...).hexdigest(); expected = token). Not reported: trivial initialisers (None, True/False, numbers, empty strings and containers), names starting with _ (deliberate discards), a value read in between (including f-strings, closures and nonlocal/global statements), self-referencing updates (x = x + 1), assignments in different branches or try/except arms, loops that continue or break between the two, functions that call locals() or vars(), module- and class-level attributes, keyword arguments inside multi-line calls, annotated and tuple assignments, docstrings and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-563/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [563],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["assignment-without-use", "dead-store", "cwe-563"],
}

_assign_re := `^([ \t]+)([A-Za-z][A-Za-z0-9_]*)\s*=\s*([^=].*)$`

_trivial := `^(?:None|True|False|-?\d[\d_.]*|""|''|b""|b''|\[\]|\{\}|\(\)|set\(\)|dict\(\)|list\(\)|tuple\(\)|str\(\))\s*(?:#.*)?$`

_indent_len(line) := count(replace(substring(line, 0, count(line) - count(trim_left(line, " \t"))), "\t", "        "))

_word(v) := concat("", [`\b`, v, `\b`])

# Statement-level assignment: not a keyword argument, not a continuation.
_statement(lines, k) if {
	t := trim_space(lines[k])
	not endswith(t, ",")
	not endswith(t, "\\")
	_opens_or_balanced(t)
	not _continues(lines, k)
}

_opens_or_balanced(t) if count(indexof_n(t, "(")) >= count(indexof_n(t, ")"))

_continues(lines, k) if {
	k > 0
	p := trim_space(lines[k - 1])
	regex.match(`[\(\[\{,\\]\s*$`, p)
}

# Inside the function whose def is the nearest one above, indented less.
_in_function(lines, i, ind) if {
	ds := [d |
		some d in numbers.range(max([0, i - 300]), i - 1)
		contains(lines[d], "def ")
		regex.match(`^\s*(?:async\s+)?def\s`, lines[d])
		_indent_len(lines[d]) < ind
	]
	count(ds) > 0
	d := max(ds)
	di := _indent_len(lines[d])
	not _dedent_between(lines, d, i, di)
}

_dedent_between(lines, a, b, lim) if {
	a + 1 <= b - 1
	some m in numbers.range(a + 1, b - 1)
	trim_space(lines[m]) != ""
	not helpers.is_comment_line(lines[m])
	_indent_len(lines[m]) <= lim
}

_dedent_below(lines, a, b, lim) if {
	a + 1 <= b - 1
	some m in numbers.range(a + 1, b - 1)
	trim_space(lines[m]) != ""
	not helpers.is_comment_line(lines[m])
	_indent_len(lines[m]) < lim
}

_read_between(lines, i, j, v) if {
	i + 1 <= j - 1
	some m in numbers.range(i + 1, j - 1)
	contains(lines[m], v)
	not helpers.is_comment_line(lines[m])
	regex.match(_word(v), lines[m])
}

_jump_between(lines, i, j) if {
	i + 1 <= j - 1
	some m in numbers.range(i + 1, j - 1)
	regex.match(`^\s*(?:continue|break)\b`, lines[m])
}

_introspective(lines, i, j) if {
	some m in numbers.range(i, min([count(lines) - 1, j + 60]))
	regex.match(`\b(?:locals|vars)\(\s*\)`, lines[m])
}

# Inside a triple-quoted string (docstring examples).
_in_docstring(lines, i) if {
	n := sum([c |
		some k in numbers.range(0, i - 1)
		l := lines[k]
		contains(l, `"""`)
		c := count(indexof_n(l, `"""`))
	]) + sum([c |
		some k in numbers.range(0, i - 1)
		l := lines[k]
		contains(l, "'''")
		c := count(indexof_n(l, "'''"))
	])
	n % 2 == 1
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "def ")
	lines := split(content, "\n")
	assigns := sort([[m[0][2], count(replace(m[0][1], "\t", "        ")), k, m[0][3]] |
		some k, l in lines
		contains(l, "=")
		m := regex.find_all_string_submatch_n(_assign_re, l, 1)
		count(m) > 0
	])
	some p in numbers.range(0, count(assigns) - 2)
	a := assigns[p]
	b := assigns[p + 1]
	a[0] == b[0]
	a[1] == b[1]
	i := a[2]
	j := b[2]
	j - i <= 40
	v := a[0]
	not startswith(v, "_")
	not regex.match(_trivial, a[3])
	not regex.match(_word(v), b[3])
	_statement(lines, i)
	_statement(lines, j)
	not _dedent_below(lines, i, j, a[1])
	not _read_between(lines, i, j, v)
	not _jump_between(lines, i, j)
	_in_function(lines, i, a[1])
	not _introspective(lines, i, j)
	not _in_docstring(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("The value assigned to '%s' is overwritten on line %d before it is read; the computation is wasted, or the code meant to use it", [v, j + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
