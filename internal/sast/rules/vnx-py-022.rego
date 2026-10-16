package vulnetix.rules.vnx_py_022

import rego.v1

import data.vulnetix.helpers

metadata := {
    "id": "VNX-PY-022",
    "name": "SQL injection via joined SQL pieces in Python",
    "description": "A SQL statement is assembled by joining a list of pieces and passed to a DB-API cursor/connection execute(), executemany() or executescript(), a Django Model.objects.raw() or pandas read_sql()/read_sql_query(), in a .py file: the call's first argument is `sep.join(parts)`, or a variable whose nearest assignment in the 20 lines above is `sep.join(parts)`. In the 20 lines above, the pieces put into the list (`parts = [...]`, `parts += [...]`, `parts.append/extend/insert(...)`, multi-line included) must contain SQL (SELECT, INSERT INTO, UPDATE ... SET, DELETE FROM, WHERE, FROM, VALUES, DROP/CREATE/ALTER TABLE, UNION), and one piece must be built from a variable by concatenation, %-formatting, str.format() or an f-string, or be a bare non-constant name (`parts.append(order)`). Use placeholders in the pieces and pass the values as a parameters argument. Not reported: SQL built in one expression (inline, through a variable, extended with +=, or a SQL template variable formatted inside the call), which is reported by VNX-PY-011; pieces with placeholders whose values are passed separately; pieces built only from UPPER_CASE constants; placeholder lists built with ','.join('?' ...); lists holding no SQL; and the calls in comments or string literals. Whether the joined variable is attacker-controlled is not judged, and a list built in another function is not traced.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-022/",
    "languages": ["python"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [89],
    "capec": ["CAPEC-66"],
    "attack_technique": ["T1059.003"],
    "cvssv4": "",
    "cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
    "tags": ["sql-injection", "database", "query"],
}

# String contents blanked (quotes kept), trailing comment removed.
_code(text) := regex.replace(
	regex.replace(regex.replace(text, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
	`#[^\n]*`, "",
)

_sink_re := `(?:\.(?:execute|executemany|executescript)|\bobjects\.raw|\bread_sql(?:_query)?)\s*\((.*)$`

_sql_re := `(?i)\b(?:select\s|insert\s+into|update\s+[\w."\x60]+\s+set|delete\s+from|where\s|from\s|values\s*\(|(?:drop|create|alter)\s+(?:table|index|view)|union\s)`

# The text from index i (starting with `first`) to the line that balances the
# parentheses opened before it (depth starts at `depth`), at most 6 lines.
_span(lines, i, first, depth) := concat(" ", array.concat([first], [lines[k] | some k in numbers.range(i + 1, e)])) if {
	not _balanced(first, depth)
	end := min([count(lines) - 1, i + 6])
	closes := [k |
		some k in numbers.range(i + 1, end)
		_balanced(concat(" ", array.concat([first], [lines[x] | some x in numbers.range(i + 1, k)])), depth)
	]
	e := _first_or(closes, end)
}

_span(_, _, first, depth) := first if _balanced(first, depth)

_balanced(text, depth) if {
	c := _code(_triple_blank(text))
	count(regex.find_all_string_submatch_n(`\)`, c, -1)) >= count(regex.find_all_string_submatch_n(`\(`, c, -1)) + depth
	not _open_triple(text)
}

_open_triple(text) if {
	n := count(regex.find_all_string_submatch_n(`"""|'''`, text, -1))
	n % 2 == 1
}

_triple_blank(text) := regex.replace(regex.replace(text, `"""[\s\S]*?"""`, `""`), `'''[\s\S]*?'''`, `''`)

_first_or(xs, _) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

_ignore := {
	"f", "r", "b", "u", "rf", "fr", "br", "rb", "F", "R", "B", "U",
	"format", "join", "str", "len", "int", "text", "None", "True", "False",
	"and", "or", "not", "in", "if", "else", "for", "is", "lambda",
}

_ids(text) := {m[0] |
	some m in regex.find_all_string_submatch_n(`[A-Za-z_]\w*`, text, -1)
	not m[0] in _ignore
}

# Expressions interpolated by an f-string, from the raw text.
_brace_ids(raw) := {id |
	some f in regex.find_all_string_submatch_n(_fstr_re, raw, -1)
	some m in regex.find_all_string_submatch_n(`\{([^{}]+)\}`, f[0], -1)
	some id in _ids(m[1])
}

# Expressions joined to a literal by +, %, or .format(), from the code text.
_op_ids(c) := {id |
	some re in [
		`\+\s*([\w.]+(?:\([^()]*\))?)`,
		`([\w.\]\[]+(?:\([^()]*\))?)\s*\+`,
		`(?:""|'')\s*%\s*(\([^()]*(?:\([^()]*\)[^()]*)*\)|[\w.]+(?:\([^()]*\))?)`,
		`\.format\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)`,
	]
	some m in regex.find_all_string_submatch_n(re, c, -1)
	some id in _ids(m[1])
}

_fstr_re := `(?:^|[^\w])[rR]?[fF][rR]?(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`

_dyn_op(raw) if {
	some m in regex.find_all_string_submatch_n(_fstr_re, raw, -1)
	contains(m[0], "{")
}

_dyn_op(raw) if {
	c := _code(_triple_blank(raw))
	regex.match(`(?:""|'')\s*\+|\+\s*[rRbBuUfF]{0,2}(?:""|'')|(?:""|'')\s*%\s*[\w(\[]|(?:""|'')\s*\.format\s*\(`, c)
}

_placeholder_list(raw) if regex.match(`join\s*\(\s*\[?\s*["'](?:\?|%s|:\w+)["']`, raw)

_placeholder_list(raw) if regex.match(`["'](?:\?|%s)\s*,?\s*["']\s*\*\s*`, raw)

# Variables in the lines above holding a placeholder list.
_placeholder_vars(lines, i) := {v |
	some j in numbers.range(max([0, i - 20]), i - 1)
	_placeholder_list(lines[j])
	v := helpers.assigned_first(lines[j])
}

_dynamic(raw, safe) if {
	_dyn_op(raw)
	not _placeholder_list(raw)
	ids := (_op_ids(_code(_triple_blank(raw))) | _brace_ids(raw)) - safe
	some id in ids
	not regex.match(`^[A-Z][A-Z0-9_]*$`, id)
}

# ── Pieces joined into the SQL ───────────────────────────────────────────
# A string built in one expression (+, %, .format(), an f-string, also
# through a variable or a `+=`) is VNX-PY-011's to report. This rule owns
# the SQL VNX-PY-011 does not follow: pieces collected in a list and joined,
# `parts.append(f"name = '{name}'")` ... `cur.execute(" ".join(parts))`.

_join_re := `^\s*(?:[rRbBuU]?(?:"[^"\n]*"|'[^'\n]*')|[A-Za-z_]\w*)\s*\.join\s*\(\s*([A-Za-z_]\w*)\s*\)`

# The call's first argument is `sep.join(parts)`.
_joined_list(_, _, raw_rest) := l if {
	m := regex.find_all_string_submatch_n(_join_re, raw_rest, 1)
	count(m) > 0
	l := m[0][1]
}

# The call's first argument is a variable whose nearest assignment in the
# 20 lines above is `sep.join(parts)`.
_joined_list(lines, i, raw_rest) := l if {
	a := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:[,)]|$)`, raw_rest, 1)
	count(a) > 0
	v := a[0][1]
	assign_re := concat("", [`^\s*`, v, `\s*=[^=](.*)$`])
	idx := [j |
		some j in numbers.range(max([0, i - 20]), i - 1)
		regex.match(assign_re, lines[j])
	]
	count(idx) > 0
	m := regex.find_all_string_submatch_n(_join_re, regex.find_all_string_submatch_n(assign_re, lines[max(idx)], 1)[0][1], 1)
	count(m) > 0
	l := m[0][1]
}

# The statements in the 20 lines above that put pieces into list l.
_pieces(lines, i, l) := [s |
	some k in numbers.range(max([0, i - 20]), i - 1)
	regex.match(concat("", [`^\s*`, l, `\s*(?:\+?=[^=]|\.(?:append|extend|insert)\s*\()`]), lines[k])
	not helpers.is_comment_line(lines[k])
	s := _span(lines, k, lines[k], 0)
]

# A piece that is a bare non-constant name: parts.append(name).
_bare_piece(s, l, safe) if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, l, `\s*\.(?:append|insert)\s*\(\s*(?:\d+\s*,\s*)?([A-Za-z_]\w*)\s*\)`]), s, 1)
	count(m) > 0
	id := m[0][1]
	not id in safe
	not id in _ignore
	not regex.match(`^[A-Z][A-Z0-9_]*$`, id)
}

_joined_sql(lines, i, raw_rest, safe) if {
	l := _joined_list(lines, i, raw_rest)
	ps := _pieces(lines, i, l)
	regex.match(_sql_re, concat("\n", ps))
	some s in ps
	_dyn_piece(s, l, safe)
}

_dyn_piece(s, _, safe) if _dynamic(s, safe)

_dyn_piece(s, l, safe) if _bare_piece(s, l, safe)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\.(?:execute|executemany|executescript)\s*\(|objects\.raw\s*\(|read_sql`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:execute|executemany|executescript)\s*\(|objects\.raw\s*\(|read_sql`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
	regex.match(_sink_re, _code(line))
	r := regex.find_all_string_submatch_n(_sink_re, line, 1)
	count(r) > 0
	safe := _placeholder_vars(lines, i)
	_reported(lines, i, r[0][1], safe)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL assembled by joining a list of pieces, one built from a variable, reaches a query call; put placeholders in the pieces and pass the values as a parameters argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_reported(lines, i, rest, safe) if _joined_sql(lines, i, rest, safe)
