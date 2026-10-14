package vulnetix.rules.vnx_go_017

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-017",
	"name": "Go SQL injection via fmt.Sprintf in db.Exec or db.Query",
	"description": "SQL text is built with fmt.Sprintf and a string verb (%s, %v) puts a value where SQL expects a literal: inside single quotes ('%s', LIKE '%%%s%%', VALUES ('%s')) or straight after a comparison (id = %s, owner = \"%s\"). Reported when that Sprintf is the query argument of a database call (Exec, Query, QueryRow, Prepare and their Context variants, sqlx Queryx/Select/Get/MustExec/NamedExec, GORM Raw), even with the call broken across lines; when its result is assigned (:=, =, +=) to a variable a later line of the function passes to such a call; or when it is a complete statement (SELECT ... FROM, INSERT INTO, UPDATE ... SET, DELETE FROM) assigned or returned. A verb in any other position (WHERE %s, ORDER BY %s, FROM %s, IN (%s)) is reported only when its argument is an HTTP request value or a variable assigned from one. Multi-line raw-string and +-joined formats are read whole. Not reported: integer verbs (%d), bind-parameter builders (fmt.Sprintf(\"$%d\", n), ILIKE %s with a placeholder variable such as ph), fragments the function assembled itself (WHERE %s with a joined clause list, a constant column list, DDL over fixed identifiers), arguments quoted or converted for SQL (pq.QuoteLiteral, QuoteIdentifier, strconv), numeric parameters, Sprintf calls inside append or another call, connection strings and messages that are not run as a query, format strings held in a variable, string literals, comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-017/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["sql-injection", "go"],
}

# Database methods whose argument is SQL text. Select/Get are also ordinary
# method names, so a call to them needs SQL in the format as well.
_db_strong := `Exec|ExecContext|Query|QueryContext|QueryRow|QueryRowContext|Prepare|PrepareContext|Queryx|QueryxContext|QueryRowx|QueryRowxContext|MustExec|MustExecContext|NamedExec|NamedExecContext|NamedQuery|NamedQueryContext|Raw`

_db_weak := `Select|SelectContext|Get|GetContext`

# A database call left open at the end of the text before fmt.Sprintf: the
# Sprintf is its first argument, or its second after a context.
_open_strong := concat("", [`\.(?:`, _db_strong, `)\(\s*(?:[\w\.\(\)&]+\s*,\s*)?$`])

_open_weak := concat("", [`\.(?:`, _db_weak, `)\(\s*(?:[\w\.\(\)&]+\s*,\s*)?$`])

# The Sprintf call: its format (one literal, or literals joined with +, raw
# strings spanning lines) and everything after it.
_sprintf_re := `fmt\.Sprintf\(\s*((?:"(?:[^"\\\n]|\\.)*"|\x60[^\x60]*\x60)(?:\s*\+\s*(?:"(?:[^"\\\n]|\\.)*"|\x60[^\x60]*\x60))*)\s*(,[\s\S]*)?$`

_verb_re := `%[-+# 0-9.*\[\]]*[a-zA-Z]`

_sql_kw := `(?i)\b(?:select|insert|update|delete|from|where|set|values|join|order\s+by|group\s+by|having|limit|union|truncate|drop|alter|returning)\b`

_sql_stmt := `(?i)\b(?:select\b[\s\S]+\bfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|merge\s+into|replace\s+into)\b`

# Values a requester chooses. A call's parentheses may have been collapsed to
# "@" when an argument list is split, so either form is accepted.
_req_src := `\b(?:r|req|request)\.(?:FormValue|PostFormValue|PathValue)[(@]|\b(?:r|req|request)\.(?:URL\.(?:Query[(@]|RawQuery|Path)|Header\.Get[(@])|\bmux\.Vars[(@]|\bchi\.URLParam[(@]|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam|GetHeader)[(@]|\.ByName[(@]`

_strip_str(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60`, `""`)

_norm_fmt(f) := out if {
	a := regex.replace(f, `["\x60]\s*\+\s*["\x60]`, "")
	b := replace(a, `\"`, `"`)
	out := replace(b, "%%", "~PCT~")
}

# The argument list after the format, split at top-level commas: strings are
# emptied and nested calls collapsed to "@", so the first ")" left closes
# fmt.Sprintf.
_args(tail) := out if {
	a := regex.replace(tail, `"(?:[^"\\\n]|\\.)*"|\x60[^\x60]*\x60|'(?:[^'\\]|\\.)*'`, `""`)
	b := regex.replace(a, `\([^()]*\)`, "@")
	c := regex.replace(b, `\([^()]*\)`, "@")
	d := regex.replace(c, `\([^()]*\)`, "@")
	head := split(d, ")")[0]
	out := [trim_space(x) | some x in split(trim_prefix(trim_space(head), ","), ",")]
}

_args("") := []

_arg_at(args, k) := args[k] if k < count(args)

_arg_at(args, k) := "" if k >= count(args)

_safe_arg(a) if regex.match(`^\s*(?:""|[0-9.]+|nil|true|false)?\s*$`, a)

_safe_arg(a) if regex.match(`(?i)(?:strconv\.|quote|escape|sanitiz|\b(?:u?int(?:8|16|32|64)?|float(?:32|64)|len|cap)@)`, a)

# A bind-parameter number or placeholder list formatted after a comparison.
_placeholder_arg(a) if regex.match(`(?i)^(?:ph\w*|\w*placeholder\w*|p\d*|pn|pos|n|idx|argn|\w*argidx|\w*argnum|bind\w*|\w*paramidx)$`, a)

_placeholder_arg(a) if regex.match(`(?i)(?:placeholder|bind|param|arg)\w*@`, a)

_placeholder_arg(a) if regex.match(`^(?:[a-z]\w*(?:Arg|Param|Placeholder|Ph)|arg|param)$`, a)

# The nearest enclosing function signature (top-level or literal).
_sig(lines, i) := lines[j] if {
	cands := [k | some k in numbers.range(max([0, i - 80]), i); contains(lines[k], "func"); regex.match(`^\s*func\b|\bfunc\s*\(`, lines[k])]
	count(cands) > 0
	j := max(cands)
}

_sig(lines, i) := "" if {
	cands := [k | some k in numbers.range(max([0, i - 80]), i); contains(lines[k], "func"); regex.match(`^\s*func\b|\bfunc\s*\(`, lines[k])]
	count(cands) == 0
}

_numeric_param(sig, a) if {
	regex.match(`^\w+$`, a)
	regex.match(concat("", [`\b`, a, `(?:\s*,\s*\w+)*\s+(?:u?int(?:8|16|32|64)?|float(?:32|64)|bool)\b`]), sig)
}

_const_name(content, a) if {
	regex.match(`^\w+$`, a)
	regex.match(concat("", [`(?m)^\s*(?:const\s+)?`, a, `\s*(?:string\s*)?=\s*["\x60]`]), content)
}

# Verb k sits inside a single-quoted SQL literal: an odd number of quotes
# before it.
_quoted(pieces, k) if {
	before := concat("", array.slice(pieces, 0, k + 1))
	count(indexof_n(before, "'")) % 2 == 1
}

# Verb k follows a comparison operator, optionally inside double quotes.
_compared(pieces, k) if regex.match(`(?i)(?:[=<>]|\blike|\bilike|\bregexp|\brlike|\bglob)\s*["\x60]?\s*$`, pieces[k])

_string_verb(v) if endswith(v, "s")

_string_verb(v) if endswith(v, "v")

# A string verb in a literal position whose argument is not converted, quoted,
# a placeholder, a number or a constant.
_value_hit(pieces, verbs, args, sig, content) if {
	some k, v in verbs
	_string_verb(v)
	_quoted(pieces, k)
	a := _arg_at(args, k)
	not _safe_arg(a)
	not _numeric_param(sig, a)
	not _const_name(content, a)
}

_value_hit(pieces, verbs, args, sig, content) if {
	some k, v in verbs
	_string_verb(v)
	not _quoted(pieces, k)
	_compared(pieces, k)
	a := _arg_at(args, k)
	not _safe_arg(a)
	not _placeholder_arg(a)
	not _numeric_param(sig, a)
	not _const_name(content, a)
}

# A string verb anywhere whose argument is a request value, directly or
# through a variable assigned from one a few lines up.
_request_hit(lines, i, verbs, args) if {
	some k, v in verbs
	_string_verb(v)
	a := _arg_at(args, k)
	not _safe_arg(a)
	regex.match(_req_src, a)
}

_request_hit(lines, i, verbs, args) if {
	some k, v in verbs
	_string_verb(v)
	a := _arg_at(args, k)
	not _safe_arg(a)
	some t in helpers.tainted_names(lines, i, 25, _req_src)
	regex.match(concat("", [`\b`, t, `\b`]), a)
}

# Where the Sprintf sits.
_inline_strong(lines, i, line) if {
	before := split(line, "fmt.Sprintf(")[0]
	prev := [lines[j] | some j in numbers.range(max([0, i - 3]), i); j < i; not helpers.is_comment_line(lines[j])]
	regex.match(_open_strong, concat(" ", array.concat(prev, [before])))
}

_inline_weak(lines, i, line) if {
	before := split(line, "fmt.Sprintf(")[0]
	prev := [lines[j] | some j in numbers.range(max([0, i - 3]), i); j < i; not helpers.is_comment_line(lines[j])]
	regex.match(_open_weak, concat(" ", array.concat(prev, [before])))
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)*(?::=|\+=|=)\s*(?:[A-Za-z_]\w*\s*\+\s*)?fmt\.Sprintf\(`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_returned(line) if regex.match(`^\s*return\s+fmt\.Sprintf\(`, line)

# The assigned variable is the query argument of a database call later in the
# same function.
_reaches_db(lines, starts, i, v) if {
	sink := concat("", [`\.(?:`, _db_strong, `|`, _db_weak, `)\(\s*(?:[\w\.\(\)&]+\s*,\s*)?`, v, `\b`])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 40]))
	contains(lines[k], v)
	regex.match(sink, lines[k])
	not helpers.is_comment_line(lines[k])
	not _func_between(starts, i, k)
}

_func_between(starts, i, k) if {
	some s in starts
	s > i
	s <= k
}

# The contexts in which the Sprintf is SQL that is run: the query argument of
# a database call, a variable later passed to one, or a complete statement.
_context(lines, i, line, _, _) := "strong" if _inline_strong(lines, i, line)

_context(lines, i, line, fmt_text, _) := "weak" if {
	not _inline_strong(lines, i, line)
	_inline_weak(lines, i, line)
	regex.match(_sql_kw, fmt_text)
}

_context(lines, i, line, fmt_text, starts) := "assigned" if {
	not _inline_strong(lines, i, line)
	v := _assigned(line)
	_assigned_sql(lines, starts, i, v, fmt_text)
}

_context(_, _, line, fmt_text, _) := "returned" if {
	_returned(line)
	regex.match(_sql_stmt, fmt_text)
}

_assigned_sql(lines, starts, i, v, _) if _reaches_db(lines, starts, i, v)

_assigned_sql(_, _, _, _, fmt_text) if regex.match(_sql_stmt, fmt_text)

_hit(_, _, _, _, pieces, verbs, args, sig, content) if _value_hit(pieces, verbs, args, sig, content)

# A request value in a fragment position counts only where the text is SQL or
# the Sprintf is itself a database call's query.
_hit(lines, i, _, fmt_text, _, verbs, args, _, _) if {
	regex.match(_sql_kw, fmt_text)
	_request_hit(lines, i, verbs, args)
}

_hit(lines, i, "strong", _, _, verbs, args, _, _) if _request_hit(lines, i, verbs, args)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "fmt.Sprintf(")
	regex.match(`(?i)\b(?:select|insert|update|delete|where|order\s+by)\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	starts := [j | some j, l in lines; startswith(l, "func ")]
	some i, line in lines
	contains(line, "fmt.Sprintf(")
	not helpers.is_comment_line(line)
	contains(_strip_str(line), "fmt.Sprintf(")
	stmt := concat("\n", array.slice(lines, i, min([count(lines), i + 14])))
	m := regex.find_all_string_submatch_n(_sprintf_re, stmt, 1)
	count(m) > 0
	fmt_text := _norm_fmt(m[0][1])
	regex.match(`%[-+# 0-9.]*[sv]`, fmt_text)
	kind := _context(lines, i, line, fmt_text, starts)
	verbs := regex.find_n(_verb_re, fmt_text, -1)
	pieces := regex.split(_verb_re, fmt_text)
	args := _args(m[0][2])
	sig := _sig(lines, i)
	_hit(lines, i, kind, fmt_text, pieces, verbs, args, sig, content)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL built with fmt.Sprintf puts a value where SQL expects a literal (or a request value into the statement) and is run as a query; pass values as bind parameters ($1, ?) and pick identifiers from an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
