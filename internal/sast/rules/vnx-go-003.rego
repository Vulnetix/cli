package vulnetix.rules.vnx_go_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-003",
	"name": "SQL injection via fmt.Sprintf",
	"description": "A SQL statement given to database/sql, sqlx, pgx or GORM (Query, QueryRow, Exec, Prepare and their Context variants, Raw, Queryx, MustExec, NamedExec, sqlx Select/Get, and GORM Where/Or/Not/Having/Joins/Order/Group) is built with fmt.Sprintf or + concatenation so that a value lands where a bind parameter belongs: inside quotes ('%s', '\" + v + \"'), after a comparison (= %s, LIKE, IN (...), VALUES (...), LIMIT/OFFSET), or anywhere when the value is read from the HTTP request (net/http, gin, echo, fiber, gorilla/mux, chi). The query may be built inline, in a variable assigned in the 40 lines above (including multi-line raw-string formats and += clauses), or split over several lines of the call. Not reported: parameterised queries ($1, ?, @name), integer verbs (%d), an identifier slot (table, column, index or database name, ORDER BY) filled from anything other than the request, placeholder lists (strings.Repeat(\"?,\"), a variable named placeholders), values quoted with pq.QuoteIdentifier/QuoteLiteral or pgx Identifier.Sanitize, query strings passed in from a caller (no builder in view), SQL-looking text that never reaches a database call, string literals and comments, and _test.go/testdata code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-003/",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["sql-injection", "injection", "database"],
}

_gate := `\.(?:Query|QueryRow|Exec|Prepare|Raw|Where|Or|Not|Having|Joins|Order|Group|Select|Get|MustExec|NamedExec|NamedQuery|Queryx|QueryRowx)(?:Context|x|xContext)?\(`

# Statement sinks: the first argument (after a context) is the SQL text.
_stmt_sink := `[\w\)\]]\.(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Raw|Queryx|QueryRowx|QueryxContext|QueryRowxContext|MustExec|MustExecContext|NamedExec|NamedExecContext|NamedQuery|NamedQueryContext)\(`

# sqlx Select/Get: a destination pointer, then the SQL text.
_sqlx_sink := `[\w\)\]]\.(?:Select|Get|SelectContext|GetContext)\(\s*(?:[\w\.]*(?:ctx|Ctx|Context\(\))\s*,\s*)?&[\w\.\[\]]+\s*,`

# GORM clause sinks: the first argument is a SQL fragment.
_clause_sink := `[\w\)\]]\.(?:Where|Or|Not|Having|Joins|Order|Group)\(`

_sinks := {"stmt": _stmt_sink, "sqlx": _sqlx_sink, "clause": _clause_sink}

_request := `\b(?:r|req|request)\.(?:FormValue|PostFormValue)\(|\b(?:r|req|request)\.URL\.Query\(\)\.Get\(|\b(?:r|req|request)\.(?:Form|PostForm|Header)\.Get\(|\bmux\.Vars\(|\.PathValue\(|\bchi\.URLParam\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|GetQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam)\(`

# A value in a bind-parameter position of a format string ...
_vpos_fmt := `(?i)'(?:%%)*%[-+#0-9.]*[sqv]|(?:=|<>|!=|<=|>=|<|>|\b(?:i?like|in|values|limit|offset|between)\b)\s*\(?\s*%[-+#0-9.]*[sqv]`

# ... or of a literal that a concatenation continues with a value.
_vpos_cat := `(?i)(?:'|(?:=|<>|!=|<=|>=|<|>|\b(?:i?like|in|values|limit|offset|between)\b)\s*\(?\s*'?)%*["\x60]\s*\+\s*[A-Za-z_(]`

# Operands that cannot carry SQL text: integer formatting and placeholder or
# bind-parameter builders ("$" + n, placeholder(len(args))).
# fmt.Sprintf with only %d verbs ("$%d"), integer formatting, and calls or
# variables named for placeholders or SQL fragments.
_neutral_sprintf := `\+\s*fmt\.Sprintf\(\s*"(?:[^"%\\]|%d|%%)*"`

_neutral_call := `\+\s*(?:strconv\.(?:Itoa|FormatInt|FormatUint|FormatFloat|FormatBool)|[\w\.]*(?:[Ii]toa|[Pp]laceholder|[Pp]aram(?:eter)?|[Bb]ind|[Aa]rg|[Pp]os|SQL|Sql|Clause|Fragment|Expr)\w*)\(`

_neutral_name := `\+\s*\w*(?:PH|Ph|[Pp]laceholders?|[Pp]aram|[Aa]rgN|[Pp]os|Idx|SQL|Sql|Clause)\b`

_neutral(text) := t3 if {
	t1 := regex.replace(text, _neutral_sprintf, "+ 0 + (\"\"")
	t2 := regex.replace(t1, _neutral_call, "+ 0 + (")
	t3 := regex.replace(t2, _neutral_name, "+ 0")
}

# Code with its string literals removed, for matching variable names.
_code_only(text) := regex.replace(text, `"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60`, `""`)

_sql_kw := `(?i)\b(?:select|insert|update|delete|from|where|values|into|join|order\s+by|group\s+by|having|union|returning|upsert|merge)\b`

_sanitised(text) if regex.match(`(?i)placeholder|\bbinds?\b|\bq?marks\b|Quote(?:Identifier|Literal)\(|\.Sanitize\(\)|strings\.Repeat\(\s*"[?$, ]`, text)

_spliced(text) if contains(text, "fmt.Sprintf(")

_spliced(text) if regex.match(`["\x60\w\)\]]\s*\+\s*["\x60\w(]`, text)

# The call text: the line, plus its argument lines when the call is broken
# after '(' or ',' (up to the closing paren line).
_stmt(lines, i, line) := line if not regex.match(`[(,+]\s*$`, line)

_stmt(lines, i, line) := s if {
	regex.match(`[(,+]\s*$`, line)
	n := count(lines) - 1
	last := min([n, i + 6])
	closers := [k | some k in numbers.range(i + 1, last); startswith(trim_space(lines[k]), ")")]
	end := min(array.concat([last], closers))
	s := concat(" ", [lines[k] | some k in numbers.range(i, end)])
}

# The sink's first argument expression: up to the first top-level comma or
# the closing paren, keeping string literals and two levels of nested calls.
_first_arg(s) := regex.replace(s, `^\s*((?:"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60|\((?:[^()"]|"(?:[^"\\]|\\.)*"|\([^()]*\))*\)|[^,()"\x60])*).*$`, "$1")

_strip_ctx(s) := regex.replace(s, `^\s*(?:ctx|context\.\w+\(\)|[\w\.]+\.Context\(\)|\w*[cC]tx\w*)\s*,\s*`, "")

# The text before the sink is not inside a string literal.
_code_prefix(prefix) if {
	p := regex.replace(prefix, `\\.`, "")
	not contains(p, "`")
	count(regex.find_all_string_submatch_n(`"`, p, -1)) % 2 == 0
}

_sql_args(stmt) := {[kind, a] |
	some kind, re in _sinks
	parts := regex.split(re, stmt)
	count(parts) > 1
	_code_prefix(parts[0])
	a := trim_space(_first_arg(_strip_ctx(parts[1])))
	a != ""
}

_kind_ok("clause", _) := true

_kind_ok(kind, text) if {
	kind != "clause"
	regex.match(_sql_kw, text)
}

_word(v) := concat("", [`\b`, v, `\b`])

_from_request(text, _) if regex.match(_request, text)

_from_request(text, tainted) if {
	count(tainted) > 0
	code := _code_only(text)
	some v in tainted
	regex.match(_word(v), code)
}

# ── the argument itself builds the query ────────────────────────────────
_injectable(_, _, kind, a, tainted) if {
	_spliced(a)
	not _sanitised(a)
	regex.match(_vpos_fmt, a)
	contains(a, "fmt.Sprintf(")
	_kind_ok(kind, a)
}

_injectable(_, _, kind, a, tainted) if {
	_spliced(a)
	not _sanitised(a)
	regex.match(_vpos_cat, _neutral(a))
	_kind_ok(kind, a)
}

_injectable(_, _, _, a, tainted) if {
	not regex.match(`^[A-Za-z_]\w*$`, a)
	not _sanitised(a)
	_from_request(a, tainted)
}

# ── the argument is a variable built a few lines up ─────────────────────
_injectable(lines, i, kind, a, tainted) if {
	regex.match(`^[A-Za-z_]\w*$`, a)
	bs := _builders(lines, i, a)
	count(bs) > 0
	all_text := concat("\n", bs)
	some t in bs
	_unsafe_builder(kind, t, all_text, tainted)
}

_unsafe_builder(kind, t, all_text, _) if {
	_spliced(t)
	not _sanitised(t)
	contains(t, "fmt.Sprintf(")
	regex.match(_vpos_fmt, t)
	_kind_ok(kind, all_text)
}

_unsafe_builder(kind, t, all_text, _) if {
	_spliced(t)
	not _sanitised(t)
	regex.match(_vpos_cat, _neutral(t))
	_kind_ok(kind, all_text)
}

_unsafe_builder(_, t, _, tainted) if {
	not _sanitised(t)
	_from_request(t, tainted)
}

# Right-hand sides of assignments (=, :=, +=) to v in the 40 lines above and
# inside the enclosing function, from the last plain assignment (which
# replaces whatever v held) onwards, each joined with its continuation lines
# (an open raw string, or a line ending in '(', ',' or '+').
_assign_re(v) := concat("", [`^\s*(?:var\s+|const\s+)?`, v, `(?:\s*,\s*\w+)*(?:\s+string)?\s*(?::=|\+=|=)[^=]`])

_builders(lines, i, v) := [t |
	start := _scope_start(lines, i)
	re := _assign_re(v)
	js := [j |
		some j in numbers.range(start, i - 1)
		contains(lines[j], v)
		not helpers.is_comment_line(lines[j])
		regex.match(re, lines[j])
	]
	resets := [j | some j in js; not regex.match(concat("", [`^\s*`, v, `\s*\+=`]), lines[j])]
	from := max(array.concat([start], resets))
	some j in js
	j >= from
	t := _rhs_text(lines, j, i)
]

_scope_start(lines, i) := s if {
	lo := max([0, i - 40])
	fns := [j | some j in numbers.range(lo, i - 1); startswith(lines[j], "func ")]
	s := max(array.concat([lo], fns))
}

_rhs_text(lines, j, i) := t if {
	last := min([i - 1, j + 10])
	ends := [k | some k in numbers.range(j, last); _complete(lines, j, k)]
	end := min(array.concat([last], ends))
	t := concat(" ", [lines[k] | some k in numbers.range(j, end)])
}

_complete(lines, j, k) if {
	ticks := sum([count(indexof_n(lines[m], "`")) | some m in numbers.range(j, k)])
	ticks % 2 == 0
	not regex.match(`[(,+]\s*$`, lines[k])
}

# Variables assigned straight from a request read (optionally trimmed or
# case-folded). A value that went through a parser or a builder function
# first (parseSort(r.URL.Query().Get("s"))) is that function's output.
_direct_request := concat("", [`(?::=|=)\s*(?:strings\.\w+\(\s*)*(?:`, _request, `)`])

_tainted(lines, i, true) := helpers.tainted_names(lines, i, 40, _direct_request)

_tainted(_, _, false) := set()

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(_gate, content)
	not helpers.is_test_path(path)
	has_request := regex.match(_request, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	stmt := _stmt(lines, i, line)
	tainted := _tainted(lines, i, has_request)
	some pair in _sql_args(stmt)
	_injectable(lines, i, pair[0], pair[1], tainted)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL statement is built with fmt.Sprintf or concatenation around a value that belongs in a bind parameter; pass it as a query argument ($1 / ?) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
