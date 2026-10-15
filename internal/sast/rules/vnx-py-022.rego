package vulnetix.rules.vnx_py_022

import rego.v1

import data.vulnetix.helpers

metadata := {
    "id": "VNX-PY-022",
    "name": "SQL injection via string concatenation in Python",
    "description": "A SQL statement is built from a variable by string concatenation (+), %-formatting, str.format() or an f-string and passed to a DB-API cursor/connection execute(), executemany() or executescript(), a Django Model.objects.raw() or pandas read_sql()/read_sql_query(), in a .py file: either in the call's own first argument (a call broken across lines is read to its closing parenthesis, triple-quoted strings included) or through a variable whose nearest assignment in the 20 lines above builds such a string (an `sql += \" AND x = '\" + v + \"'\"` after a SQL assignment counts), or a variable holding a SQL string literal formatted inside the call (`cur.execute(sql % name)`, `cur.execute(tmpl.format(a))`). The string must contain SQL (SELECT, INSERT INTO, UPDATE ... SET, DELETE FROM, WHERE, FROM, VALUES, DROP/CREATE/ALTER TABLE, UNION). Use driver placeholders (?, %s, %(name)s) with a parameters argument. Not reported: parameterised calls, including a %s inside the literal followed by a parameters tuple; strings whose interpolated parts are all UPPER_CASE constants; placeholder lists built with ','.join('?' ...); execute() of a string with no SQL (a shell runner's execute); and the calls in comments or string literals. Whether the interpolated variable is attacker-controlled is not judged, and a query built in another function is not traced. VNX-PY-011 reports overlapping shapes.",
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

# Sink argument is the dynamic SQL string itself.
_direct(lines, i, raw_rest, safe) if {
	text := _span(lines, i, raw_rest, 1)
	regex.match(_sql_re, text)
	_dynamic(text, safe)
}

# Sink argument is a variable built from dynamic SQL above.
_via_var(lines, i, raw_rest, safe) if {
	a := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:[,)]|$)`, raw_rest, 1)
	count(a) > 0
	v := a[0][1]
	assign_re := concat("", [`^\s*`, v, `\s*=[^=](.*)$`])
	idx := [j |
		some j in numbers.range(max([0, i - 20]), i - 1)
		regex.match(assign_re, lines[j])
	]
	count(idx) > 0
	j := max(idx)
	m := regex.find_all_string_submatch_n(assign_re, lines[j], 1)
	base := _span(lines, j, m[0][1], 0)
	regex.match(_sql_re, base)
	_built(lines, j, i, v, base, safe)
}

_built(_, _, _, _, base, safe) if _dynamic(base, safe)

_built(lines, j, i, v, _, safe) if {
	some k in numbers.range(j + 1, i - 1)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, v, `\s*\+=\s*(.*)$`]), lines[k], 1)
	count(m) > 0
	_dynamic(m[0][1], safe)
}

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
		"message": "SQL built by string concatenation or formatting reaches a query call; use parameterised queries (placeholders plus a parameters argument)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_reported(lines, i, rest, safe) if _direct(lines, i, rest, safe)

_reported(lines, i, rest, safe) if _via_var(lines, i, rest, safe)

_reported(lines, i, rest, safe) if _via_fmt(lines, i, rest, safe)

# A SQL template held in a variable and formatted inside the call:
# sql = "... '%s'" ; cur.execute(sql % name) / cur.execute(tmpl.format(a)).
_via_fmt(lines, i, raw_rest, safe) if {
	a := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(%|\.format\s*\()\s*(.*)$`, _code(raw_rest), 1)
	count(a) > 0
	v := a[0][1]
	operands := _fmt_operands(a[0][2], a[0][3])
	ids := _ids(operands) - safe
	some id in ids
	not regex.match(`^[A-Z][A-Z0-9_]*$`, id)
	_sql_template(lines, i, v)
}

# For %, the operand up to the parameters comma: `sql % name, params`.
_fmt_operands("%", rest) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^(\([^()]*(?:\([^()]*\)[^()]*)*\)|[\w.]+(?:\([^()]*\))?)`, rest, 1)
	count(m) > 0
}

_fmt_operands(op, rest) := m[0][1] if {
	op != "%"
	m := regex.find_all_string_submatch_n(`^([^()]*(?:\([^()]*\)[^()]*)*)\)`, rest, 1)
	count(m) > 0
}

# The variable's nearest assignment above (module level included) is a SQL
# string literal.
_sql_template(lines, i, v) if {
	assign_re := concat("", [`^\s*`, v, `\s*=\s*[rRbBuU]?(?:"|')(.*)$`])
	idx := [j |
		some j in numbers.range(max([0, i - 20]), i - 1)
		regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), lines[j])
	]
	count(idx) > 0
	j := max(idx)
	m := regex.find_all_string_submatch_n(assign_re, lines[j], 1)
	count(m) > 0
	regex.match(_sql_re, _span(lines, j, m[0][1], 0))
}
