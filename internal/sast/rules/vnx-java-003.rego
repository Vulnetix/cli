package vulnetix.rules.vnx_java_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-003",
	"name": "SQL injection via string concatenation",
	"description": "Reports a JDBC, Spring JdbcTemplate, Hibernate createSQLQuery or Android SQLite query whose SQL text is built at run time: the query argument of Statement.executeQuery/executeUpdate/executeLargeUpdate/execute/addBatch, Connection.prepareStatement/prepareCall/nativeSQL, JdbcTemplate (or NamedParameterJdbcTemplate) query/queryForObject/queryForList/queryForMap/queryForRowSet/queryForStream/update/batchUpdate/execute, Session.createSQLQuery, or SQLiteDatabase.rawQuery/execSQL is a concatenation or String.format/concat with a non-constant value, a request value, or a variable assigned that way within the 40 lines above (including multi-line `query =\\n \"...\" + name` and `sql += value`). Not reported: a constant query or one concatenated only from literals and UPPER_CASE constants, a parameterised query whose values are bound with ? placeholders, a query that arrives as a plain method parameter (its callers decide), JPQL/HQL createQuery/createNativeQuery (VNX-JAVA-015), execute() on receivers that are not SQL statements or templates (HTTP clients, executors), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-003/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["sql-injection", "jdbc", "injection"],
}

# ── Shared expression helpers ────────────────────────────────────────────

# String and char literals emptied, so a quoted "+" or "exec(" is not code.
_strip(s) := regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)'`, `''`)

_joined(lines, i, span, strip) := concat(" ", [t |
	some k in numbers.range(i, min([count(lines) - 1, i + span]))
	t := _maybe_strip(lines[k], strip)
])

_maybe_strip(l, true) := _strip(l)

_maybe_strip(l, false) := l

# The text after the call opened by `re` on line i, up to the first `;`,
# over up to four lines (a call broken across lines).
_after(text, re) := a if {
	m := regex.find_all_string_submatch_n(concat("", [re, `([^;]*)`]), text, 1)
	count(m) > 0
	a := m[0][count(m[0]) - 1]
}

_const_ident(id) if regex.match(`^(?:\w+\.)*[A-Z][A-Z0-9_]*$`, id)

_const_ident(id) if id in {"true", "false", "null"}

_nonconst_operand(")")

_nonconst_operand(id) if {
	id != ")"
	not _const_ident(id)
}

# A `+` with a non-literal, non-constant operand on either side.
_nonconst_concat(expr) if {
	s := regex.replace(expr, `\+\+|\+=`, " ")
	contains(s, "+")
	some m in regex.find_all_string_submatch_n(`\+\s*([A-Za-z_][\w.]*)|([A-Za-z_][\w.]*|\))\s*\+`, s, -1)
	_nonconst_operand(concat("", [m[1], m[2]]))
}

_formats(expr) if regex.match(`\b(?:String|MessageFormat)\.format\s*\([^)]*,\s*[A-Za-z_(]|\.formatted\s*\(\s*[A-Za-z_]|\.concat\s*\(\s*[A-Za-z_]`, expr)

_kw := {"new", "null", "true", "false", "this", "super", "return", "instanceof", "final"}

# Local names an expression reads (not fields after a dot, not calls).
_idents(expr) := {v |
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w."'])([a-z_]\w*)(\s*\()?`, expr, -1)
	m[2] == ""
	v := m[1]
	not v in _kw
}

_src_re := `\b(?:getParameter(?:Values|Map)?|getHeaders?|getQueryString|getCookies|getInputStream|getReader|getPathInfo|readLine|nextLine)\s*\(`

_param_re := `@(?:RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue|QueryParam|PathParam|FormParam|HeaderParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.]+(?:<[^>]*>)?(?:\[\])?\s+`

_win(i) := max([0, i - 40])

# The right-hand side of an assignment to v on line j (up to `;`).
_rhs(lines, j, v) := r if {
	pat := concat("", [`(?:^|[^\w.])`, v, `\s*(?:\[\s*\])?\s*\+?=\s*([^=;][^;]*|$)`])
	regex.match(pat, _strip(lines[j]))
	not helpers.is_comment_line(lines[j])
	r := _after(_joined(lines, j, 6, true), concat("", [`(?:^|[^\w.])`, v, `\s*(?:\[\s*\])?\s*\+?=`]))
}

# v holds a request value: assigned from a source, or an annotated parameter.
_src_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	regex.match(_src_re, _rhs(lines, j, v))
}

_src_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i)
	contains(lines[j], v)
	regex.match(concat("", [_param_re, v, `\b`]), _strip(lines[j]))
}

# v holds run-time built text or a request value.
_tainted(lines, i, v) if _src_tainted(lines, i, v)

_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	_dynamic(r)
}

_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], v)
	r := _rhs(lines, j, v)
	some w in _idents(r)
	w != v
	_src_tainted(lines, j, w)
}

# cmd += value: appending a non-constant builds the text at run time.
_tainted(lines, i, v) if {
	some j in numbers.range(_win(i), i - 1)
	contains(lines[j], "+=")
	contains(lines[j], v)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, v, `\s*\+=\s*([^;]*)`]), _strip(lines[j]), 1)
	count(m) > 0
	_nonconst_concat(concat("", ["x + ", m[0][1]]))
}

_dynamic(e) if _nonconst_concat(e)

_dynamic(e) if _formats(e)

_dynamic(e) if regex.match(_src_re, e)

_bad(_, _, a) if _dynamic(a)

_bad(lines, i, a) if {
	some v in _idents(a)
	_tainted(lines, i, v)
}

# ── Rule-specific ────────────────────────────────────────────────────────

# Methods whose first argument is SQL text whatever the receiver is called.
_jdbc_only := `\.(executeQuery|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|prepareCall|nativeSQL|createSQLQuery|rawQuery|execSQL)\s*\(`

# execute() and the JdbcTemplate verbs are SQL only on a statement or template.
_receiver_sql := `(?i)\b(\w*(?:stmt|statement|jdbc|template|conn|connection|session|db|database)\w*)\s*\.\s*(?:execute|query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|queryForLong|queryForInt|update|batchUpdate)\s*\(`

_sink_re := `\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|prepareCall|nativeSQL|createSQLQuery|rawQuery|execSQL|execute|query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|queryForLong|queryForInt|update|batchUpdate)\s*\(`

_is_sink(sline) if regex.match(_jdbc_only, sline)

_is_sink(sline) if {
	regex.match(_receiver_sql, sline)
	not regex.match(`(?i)\b(?:http\w*|client|executor\w*|task\w*|digest|md|mac|signature|signer|verifier|hasher|cipher|crc\w*|checksum)\s*\.`, sline)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?i)select|insert|update|delete|where|from |sql|query`, content)
	regex.match(`\.\s*(?:execute|query|update|batchUpdate|addBatch|prepare|nativeSQL|createSQLQuery|rawQuery|execSQL)\w*\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.\s*(?:execute|query|update|batchUpdate|addBatch|prepare|nativeSQL|createSQLQuery|rawQuery|execSQL)\w*\s*\(`, line)
	not helpers.is_comment_line(line)
	sline := _strip(line)
	_is_sink(sline)
	a := _first_arg(_after(_joined(lines, i, 4, true), _sink_re))
	_bad(lines, i, a)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL text is built from run-time data; use a PreparedStatement (or JdbcTemplate) with ? placeholders and bind the values",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The first top-level argument of an argument list (bound values after a
# comma are parameters, not SQL).
_first_arg(a) := f if {
	parts := regex.find_all_string_submatch_n(`^((?:[^,()]|\((?:[^()]|\([^()]*\))*\))*)`, a, 1)
	count(parts) > 0
	f := parts[0][1]
}
