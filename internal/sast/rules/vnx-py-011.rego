package vulnetix.rules.vnx_py_011

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-011",
	"name": "Python SQL injection",
	"description": "SQL text is built from a non-constant value with an f-string, % formatting, str.format() or + concatenation and passed to a database API, so the value can change the statement (SQL injection). Reported: the first argument of cursor/connection/session .execute(), .executemany(), .executescript(), .mogrify(), asyncpg/databases .fetch()/.fetchrow()/.fetchval()/.fetch_all()/.fetch_one(), pandas read_sql()/read_sql_query(), Django Model.objects.raw(), QuerySet.extra(), RawSQL() and SQLAlchemy text() (when the file uses sqlalchemy) is such an expression, including on continuation lines of a multi-line call; or is a variable assigned or extended (+=) by such an expression up to 25 lines above; or formats a SQL template variable inside the call (`cur.execute(tmpl.format(name))`, `cur.execute(sql % name)`) whose nearest assignment in the 25 lines above is a SQL string literal (the template variable itself does not count as a value). The string must look like SQL (a keyword such as SELECT/WHERE/ORDER BY or a comparison), except when a variable named like a query (sql, query, stmt) is itself formatted in the call. Not reported: psycopg sql.SQL(...).format(sql.Identifier(...)) composition, parameterised calls (placeholders in a literal with the values passed separately, including a % or + inside the parameter tuple), f-strings without interpolation, interpolation of ALL_CAPS constants only, placeholder lists built with ','.join('?' ...) or a variable named placeholders, constant concatenation, non-SQL text passed to an unrelated .execute()/.raw(), and the pattern inside strings and comments. Queries assembled in another function, or through more than one intermediate variable, are not followed; SQL assembled from a list of pieces and join()ed is reported by VNX-PY-022.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-011/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["sql-injection", "django", "sqlalchemy", "database"],
}

# ── String handling ─────────────────────────────────────────────────────

_str_re := `[rRbBuU]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')`

# An f-string literal (any quoting) containing at least one interpolation.
_fstr_re := `(?:^|[^\w])[rR]?[fF][rR]?(?:"""[^{]*?\{[\s\S]*?"""|'''[^{]*?\{[\s\S]*?'''|"(?:[^"\\\n{]|\\.)*\{(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n{]|\\.)*\{(?:[^'\\\n]|\\.)*')`

# Literals become tokens: FSTR for an interpolating f-string, QSTR for the rest.
_blank(s) := regex.replace(regex.replace(s, _fstr_re, " FSTR "), _str_re, " QSTR ")

# Strings blanked (any kind) and trailing comments dropped, for finding the call.
_code(line) := regex.replace(regex.replace(line, _str_re, " QSTR "), `#.*$`, "")

# The first argument of a call: strings, bracketed groups (two levels) and any
# character that is not a top-level comma or the closing parenthesis.
_arg_re := `^(?:[rRbBuUfF]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\[(?:[^\[\]]|\[[^\[\]]*\])*\]|\{[^{}]*\}|[^,()\[\]{}"'])*`

_first_arg(after) := m[0] if {
	m := regex.find_n(_arg_re, after, 1)
	count(m) > 0
}

# ── Is the expression built from a value? ───────────────────────────────

_dyn_shape(b) if contains(b, "FSTR")

_dyn_shape(b) if regex.match(`QSTR\s*%`, b)

_dyn_shape(b) if regex.match(`[\w\)\]]\s*%\s*[\w(\[]`, b)

_dyn_shape(b) if regex.match(`\.format\s*\(`, b)

_dyn_shape(b) if contains(b, "+")

# Names the expression reads: identifiers outside literals (callees and
# keyword-argument names excluded) and the names interpolated in f-strings.
_outside_ids(b) := {m[1] |
	cleaned := regex.replace(regex.replace(b, `QSTR|FSTR`, " "), `([A-Za-z_]\w*)\s*=[^=]`, " ")
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)(\s*\()?`, cleaned, -1)
	m[2] == ""
}

_interp_ids(raw) := {m[1] |
	some f in regex.find_all_string_submatch_n(_fstr_re, raw, -1)
	some inner in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, f[0], -1)
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)(\s*\()?`, regex.replace(inner[1], `![rsa]$|:[^}]*$`, ""), -1)
	m[2] == ""
}

_benign_id(x) if regex.match(`^[A-Z][A-Z0-9_]*$`, x)

_benign_id(x) if regex.match(`(?i)placeholder|qmark|^marks$|^QSTR$|^FSTR$`, x)

_benign_id(x) if x in {"self", "cls", "None", "True", "False", "if", "else", "for", "in", "and", "or", "not"}

_unsafe_ids(raw, b) := {x |
	some x in _outside_ids(b) | _interp_ids(raw)
	not _benign_id(x)
}

_placeholders(raw) if regex.match(`\.join\(\s*[\[(]?\s*["'](?:\?|%s|:\w+)["']|["'](?:\?|%s)["']\s*\]?\s*\*\s*len\(`, raw)

# psycopg sql.SQL(...).format(sql.Identifier(...)) composes identifiers and
# literals safely.
_composed(raw) if regex.match(`(?:^|[^\w.])(?:sql\.)?SQL\s*\(\s*[rRbBuU]{0,2}["']`, raw)

_dynamic(raw) if _dynamic_x(raw, set())

# skip: names that are the template being formatted, not values put into it.
_dynamic_x(raw, skip) if {
	b := _blank(raw)
	_dyn_shape(b)
	count(_unsafe_ids(raw, b) - skip) > 0
	not _placeholders(raw)
	not _composed(raw)
}

# `tmpl % args` / `tmpl.format(args)`: tmpl is the SQL template; only the
# values formatted into it can change the statement.
_lead_fmt(arg) := {m[0][1]} if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:%|\.format\s*\()`, arg, 1)
	count(m) > 0
} else := set()

# The template variable's nearest assignment in the 25 lines above is a SQL
# string literal: tmpl = "UPDATE users SET nick = '{}'"; cur.execute(tmpl.format(n)).
_sql_template(lines, i, v) if {
	idx := [j |
		some j in numbers.range(max([0, i - 25]), i - 1)
		regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), lines[j])
	]
	count(idx) > 0
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, v, `\s*=\s*[rRbBuU]?((?:"""|'''|"|')[\s\S]*)$`]), lines[max(idx)], 1)
	count(m) > 0
	_sqlish(m[0][1])
}

_sqlish(raw) if regex.match(`(?i)\b(?:select|insert|update|delete|from|where|values|create|drop|alter|pragma|truncate|grant|revoke|show|describe|union|order\s+by|group\s+by|limit|join|like|set|exec)\b|\s=\s*['"%{]|=\s*'|=\s*%`, raw)

# query % args, sql.format(...), stmt + where: the formatted name says it is SQL.
_sqlish(raw) if regex.match(`(?i)^\s*\w*(?:sql|query|stmt|statement)\w*\s*(?:%|\.format\s*\(|\+)`, raw)

# ── Sinks ───────────────────────────────────────────────────────────────

_sink_re(content) := `(?:\.(?:execute|executemany|executescript|mogrify|raw|extra|fetch|fetchrow|fetchval|fetch_all|fetch_one|read_sql|read_sql_query)|(?:^|[^\w.])RawSQL|(?:^|[^\w])text)\s*\(` if contains(content, "sqlalchemy")

_sink_re(content) := `(?:\.(?:execute|executemany|executescript|mogrify|raw|extra|fetch|fetchrow|fetchval|fetch_all|fetch_one|read_sql|read_sql_query)|(?:^|[^\w.])RawSQL)\s*\(` if not contains(content, "sqlalchemy")

# The raw text after the sink's opening parenthesis, through up to 6 lines.
_after(lines, i, sink) := pieces[1] if {
	joined := concat("\n", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 6]))])
	pieces := regex.split(sink, joined)
	count(pieces) > 1
}

_bal(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# The right-hand side of an assignment on line j, with continuation lines while
# a parenthesis stays open (at most 4).
_rhs(lines, j, first) := first if _bal(_code(first)) <= 0

_rhs(lines, j, first) := txt if {
	_bal(_code(first)) > 0
	last := min([count(lines) - 1, j + 4])
	txt := concat("\n", array.concat([first], [lines[k] | some k in numbers.range(j + 1, last)]))
}

# The bare variable passed to the sink was built dynamically a few lines up.
_built_above(lines, i, v) if {
	some j in numbers.range(max([0, i - 25]), i - 1)
	line := lines[j]
	contains(line, v)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, v, `\s*(\+?=)\s*([^=][\s\S]*)$`]), line, 1)
	count(m) > 0
	rhs := _rhs(lines, j, m[0][2])
	_assign_dynamic(m[0][1], rhs)
}

# v = <dynamic SQL>; v += <anything that is not a constant>
_assign_dynamic("=", rhs) if {
	_dynamic(rhs)
	_sqlish(rhs)
}

_assign_dynamic("+=", rhs) if {
	count(_unsafe_ids(rhs, _blank(rhs))) > 0
	not _placeholders(rhs)
}

_reported(_, arg) if {
	_dynamic_x(arg, _lead_fmt(arg))
	_sqlish(arg)
}

_reported(lines, arg) if {
	skip := _lead_fmt(arg)
	some v in skip
	_dynamic_x(arg, skip)
	some i in [lines.i]
	_sql_template(lines.lines, i, v)
}

_reported(lines, arg) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*$`, arg, 1)
	count(m) > 0
	v := m[0][1]
	not _benign_id(v)
	some i in [lines.i]
	_built_above(lines.lines, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?:execute\w*|mogrify|raw|extra|RawSQL|text|fetch(?:row|val|_all|_one)?|read_sql\w*)\s*\(`, content)
	sink := _sink_re(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:execute|mogrify|raw|extra|RawSQL|text|fetch|read_sql)`, line)
	not helpers.is_comment_line(line)
	regex.match(sink, _code(line))
	after := _after(lines, i, sink)
	arg := _first_arg(after)
	_reported({"lines": lines, "i": i}, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL statement built with an f-string, % formatting, .format() or concatenation from a variable; pass the values as query parameters (cursor.execute(sql, params), text() with bound :names) instead of formatting them into the SQL",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
