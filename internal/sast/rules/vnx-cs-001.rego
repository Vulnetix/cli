package vulnetix.rules.vnx_cs_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-001",
	"name": "C# SQL injection: query text built by concatenation, interpolation or string.Format",
	"description": "A SQL statement is executed whose text is assembled from non-constant values instead of bound parameters. Reported: an ADO.NET command or data adapter (new SqlCommand/SqlDataAdapter and the OleDb, Odbc, Oracle, MySql, Npgsql, Sqlite, SqlCe and DB2 equivalents, including target-typed new) or a CommandText assignment (statement or object initializer) whose text uses + with a non-constant operand, an interpolated string with a non-constant hole, string.Format/string.Concat or a StringBuilder filled that way; EF Core FromSqlRaw/ExecuteSqlRaw(Async)/SqlQueryRaw, and FromSql/ExecuteSqlCommand/SqlQuery with concatenation (or with interpolation under EF6, where those take a plain string); Dapper Query/Execute methods and LINQ-to-SQL ExecuteQuery/ExecuteCommand with a SQL literal built the same way. The query may be built inline, across several lines, or in a variable assigned or appended to (+=, Append, AppendFormat) up to 30 lines above the call. Not reported: @/:/$ parameter placeholders with Parameters.Add/AddWithValue, Dapper parameter objects, FromSqlInterpolated/ExecuteSqlInterpolated and FormattableString queries, concatenation of const or static readonly fields, ALL_CAPS constants and nameof(), placeholder lists built from \"@p\" + i, stored-procedure names, comparisons, and the pattern in comments and log strings. A query string received as a method parameter and built by the caller is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-001/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["sql-injection", "csharp"],
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_file_needles := {"Command", "DataAdapter", "FromSql", "ExecuteSql", "SqlQuery", "Dapper", "ExecuteQuery"}

_line_needles := {"Command", "DataAdapter", "FromSql", "ExecuteSql", "SqlQuery", "Query", "Execute"}

# String contents are blanked before a sink is recognised, so a log message
# that spells "new SqlCommand(" or "CommandText = " is not a call.
_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

_providers := `(?:Sql|SqlCe|OleDb|Odbc|Oracle|MySql|Npgsql|Sqlite|SQLite|DB2|Db2|Fb|Ifx)`

# Sinks: kind, and the regex whose match ends at the start of the query text.
_sinks := [
	{"kind": "ado", "re": concat("", [`\bnew\s+(?:[\w]+\.)*`, _providers, `(?:Command|DataAdapter)\s*\(`])},
	{"kind": "ado", "re": concat("", [`\b`, _providers, `(?:Command|DataAdapter)\s+\w+\s*=\s*new\s*\(`])},
	{"kind": "ado", "re": `\bCommandText\s*=\s*`},
	{"kind": "raw", "re": `\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw)\s*(?:<[^>()]*>)?\s*\(`},
	{"kind": "ef", "re": `\.(?:FromSql|ExecuteSqlCommand|ExecuteSqlCommandAsync|SqlQuery)\s*(?:<[^>()]*>)?\s*\(`},
	{"kind": "dapper", "re": `\.(?:Query|QueryAsync|QueryFirst|QueryFirstAsync|QueryFirstOrDefault|QueryFirstOrDefaultAsync|QuerySingle|QuerySingleAsync|QuerySingleOrDefault|QuerySingleOrDefaultAsync|QueryMultiple|QueryMultipleAsync|Execute|ExecuteAsync|ExecuteScalar|ExecuteScalarAsync|ExecuteReader|ExecuteReaderAsync)\s*(?:<[^>()]*>)?\s*\(`},
	{"kind": "linq", "re": `\.(?:ExecuteQuery|ExecuteCommand)\s*(?:<[^>()]*>)?\s*\(`},
]

_sql_keyword := `(?i)\b(select\s[\s\S]*\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|exec(ute)?\s|merge\s+into|where\s)`

# ── Statement text ───────────────────────────────────────────────────────
# A statement runs from line k to the first line holding a ';', opening a
# block, or followed by a line that opens one (a using/if header), at most
# eight lines on.
_ends_stmt(lines, j) if contains(lines[j], ";")

_ends_stmt(lines, j) if contains(lines[j], "{")

_ends_stmt(lines, j) if {
	j + 1 < count(lines)
	startswith(trim_space(lines[j + 1]), "{")
}

_stmt_end(lines, k) := e if {
	last := min([count(lines) - 1, k + 8])
	ends := [j | some j in numbers.range(k, last); _ends_stmt(lines, j)]
	count(ends) > 0
	e := ends[0]
}

_stmt_end(lines, k) := last if {
	last := min([count(lines) - 1, k + 8])
	ends := [j | some j in numbers.range(k, last); _ends_stmt(lines, j)]
	count(ends) == 0
}

_stmt(lines, k) := concat(" ", array.slice(lines, k, _stmt_end(lines, k) + 1))

# ── Constants ────────────────────────────────────────────────────────────

_const_expr(e, _) if regex.match(`^(\w+\.)*[A-Z][A-Z0-9_]+$`, e)

_const_expr(e, consts) if e in consts

_const_expr(e, consts) if {
	parts := split(e, ".")
	parts[count(parts) - 1] in consts
}

_const_expr(e, _) if startswith(e, "nameof")

_const_expr(e, _) if startswith(e, "typeof")

_const_expr(e, _) if regex.match(`^\d`, e)

_const_expr(e, _) if e in {"Environment.NewLine", "string.Empty", "String.Empty"}

# A list joined from parameter placeholders ("@p" + i) is placeholders.
_const_expr(e, ctx) if {
	e in {"string.Join", "String.Join"}
	"__placeholders__" in ctx
}

# ── Dynamic text ─────────────────────────────────────────────────────────

_interpolated(t) if regex.match(`\$+@?"|@\$+"`, t)

_dyn(t, _, _, _) if regex.match(`\b[Ss]tring\s*\.\s*(Format|Concat)\s*\(|\.AppendFormat\s*\(`, t)

_dyn(t, ctx, _, true) if {
	_interpolated(t)
	some h in regex.find_all_string_submatch_n(`\{([^{}"]+)\}`, t, -1)
	e := trim_space(regex.replace(h[1], `[:,].*$`, ""))
	e != ""
	not regex.match(`^\d+$`, e)
	not _const_expr(e, ctx)
}

# operand after a literal: "..." + x
_dyn(t, ctx, self, _) if {
	t2 := regex.replace(t, `[@:$]\w*"\s*\+\s*[A-Za-z_][\w.]*`, `"`)
	some m in regex.find_all_string_submatch_n(`"\s*\+\s*\(?\s*([A-Za-z_][\w.]*)`, t2, -1)
	not _const_expr(m[1], ctx)
	m[1] != self
}

# operand before a literal: x + "..."
_dyn(t, ctx, self, _) if {
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*)(?:\([^()]*\))?\s*\+\s*\$?@?"`, t, -1)
	not _const_expr(m[1], ctx)
	m[1] != self
}

# Whether an interpolated string is unsafe for this sink: EF Core's FromSql,
# SqlQuery and ExecuteSqlCommand take a FormattableString and bind its holes;
# under EF6 (System.Data.Entity) they take a plain string.
_interp_unsafe(kind, _) := true if kind != "ef"

_interp_unsafe("ef", content) := true if contains(content, "System.Data.Entity")

_interp_unsafe("ef", content) := false if not contains(content, "System.Data.Entity")

# The kinds that only count when the text is recognisably SQL.
_needs_sql("dapper")

_needs_sql("linq")

_sql_ok(kind, _) if not _needs_sql(kind)

_sql_ok(kind, t) if {
	_needs_sql(kind)
	regex.match(_sql_keyword, t)
}

# The statement from the assignment on, so the operator (+=, AppendFormat)
# stays in the text.
_from(stmt, re) := substring(stmt, indexof(stmt, m), -1) if {
	m := regex.find_n(re, stmt, 1)[0]
}

# The query text after the sink.
_after(stmt, re) := substring(stmt, idx + count(m), -1) if {
	m := regex.find_n(re, stmt, 1)[0]
	idx := indexof(stmt, m)
}

# ── Inline query text ────────────────────────────────────────────────────

_unsafe(lines, content, i, kind, arg, ctx) if {
	_dyn(arg, ctx, "", _interp_unsafe(kind, content))
	_sql_ok(kind, arg)
}

# ── Query text from a variable built above ───────────────────────────────

_query_var(arg) := v if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:[,);}]|$)`, arg, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"null", "true", "false", "new"}
}

_query_var(arg) := v if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\.ToString\(\s*\)`, arg, 1)
	count(m) > 0
	v := m[0][1]
}

# A FormattableString keeps its holes as parameters.
_formattable(lines, i, v) if {
	some k in numbers.range(max([0, i - 30]), i)
	regex.match(concat("", [`\bFormattableString\s+`, v, `\b`]), lines[k])
}

# A member declaration line: the look-back never crosses into another method.
_member_decl(line) if regex.match(`^\s*(?:(?:public|private|protected|internal|static|override|virtual|async)\s+)+[^=;(]*\(`, line)

# The look-back window for v: from the last plain assignment of v (a later
# `v = "..."` replaces what was built before) or the start of the method.
_window_start(lines, i, v) := s if {
	lo := max([0, i - 30])
	plain_re := concat("", [`(^|[^\w.])`, v, `\s*=\s*([^=]|$)`])
	decls := [k | some k in numbers.range(lo, i - 1); _member_decl(lines[k])]
	base := max(array.concat([lo], decls))
	assigns := [k |
		some k in numbers.range(base, i - 1)
		contains(lines[k], v)
		not helpers.is_comment_line(lines[k])
		regex.match(plain_re, lines[k])
	]
	s := max(array.concat([base], assigns))
}

_unsafe(lines, content, i, kind, arg, ctx) if {
	v := _query_var(arg)
	not _formattable(lines, i, v)
	i > 0
	assign_re := concat("", [`(^|[^\w.])`, v, `\s*(\+?=|\.Append(Line|Format)?\s*\()`])
	some k in numbers.range(_window_start(lines, i, v), i - 1)
	contains(lines[k], v)
	not helpers.is_comment_line(lines[k])
	regex.match(assign_re, lines[k])
	not regex.match(concat("", [`\b`, v, `\s*==`]), lines[k])
	s := _stmt(lines, k)
	rhs := _from(s, assign_re)
	_dyn(rhs, ctx, v, true)
	_sql_ok(kind, rhs)
}

_unsafe_sink(lines, content, i, line, ctx) if {
	code := _code(line)
	some sink in _sinks
	regex.match(sink.re, code)
	sink.kind != "dapper"
	not regex.match(`\bCommandText\s*==`, code)
	arg := _after(_stmt(lines, i), sink.re)
	_unsafe(lines, content, i, sink.kind, arg, ctx)
}

_unsafe_sink(lines, content, i, line, ctx) if {
	contains(content, "Dapper")
	code := _code(line)
	some sink in _sinks
	sink.kind == "dapper"
	regex.match(sink.re, code)
	arg := _after(_stmt(lines, i), sink.re)
	_unsafe(lines, content, i, sink.kind, arg, ctx)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	_has_any(content, _file_needles)
	lines := split(content, "\n")
	consts := {m[1] |
		some l in lines
		contains(l, "const ")
		some m in regex.find_all_string_submatch_n(`\bconst\s+[\w.<>?]+\s+(\w+)\s*=`, l, -1)
	} | {m[1] |
		some l in lines
		contains(l, "readonly")
		some m in regex.find_all_string_submatch_n(`\bstatic\s+readonly\s+string\s+(\w+)\s*=\s*@?"`, l, -1)
	}
	ph := {"__placeholders__" | regex.match(`[@:$]\w*"\s*\+\s*[A-Za-z_]`, content)}
	ctx := consts | ph
	some i, line in lines
	_has_any(line, _line_needles)
	not helpers.is_comment_line(line)
	_unsafe_sink(lines, content, i, line, ctx)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL text is built from a non-constant value (concatenation, interpolation or string.Format) and executed: the value can change the statement. Use @parameters with Parameters.Add, a Dapper parameter object, or FromSqlInterpolated/ExecuteSqlInterpolated",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
