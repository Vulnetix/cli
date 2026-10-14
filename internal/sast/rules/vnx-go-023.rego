package vulnetix.rules.vnx_go_023

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-023",
	"name": "SQL injection via string concatenation",
	"description": "A value is concatenated onto SQL text where SQL expects a literal: after an opening single quote (name = '\" + name + \"', LIKE '%\" + term + \"%', IN ('\" + strings.Join(ids, \"','\") + \"')) or straight after a comparison (id = \" + id). Reported when the concatenation is inside the query argument of a database call (Exec, Query, QueryRow, Prepare and their Context variants, sqlx, GORM Raw); when the statement is assigned (:=, =, +=) to a variable a later line of the function passes to such a call; or when it is a complete statement (SELECT ... FROM, INSERT INTO, UPDATE ... SET, DELETE FROM) assigned or returned. Statements split over several lines with + and raw strings that span lines are read whole, and the finding is on the line of the concatenation. A value in any other position (ORDER BY \" + col, FROM \" + table) is reported only when it is an HTTP request value or a variable assigned from one. Not reported: fragments the function built itself (\" WHERE \" + strings.Join(clauses, \" AND \"), a constant column list, a FROM clause), bind-parameter numbers ($\" + strconv.Itoa(n)), values converted or quoted for SQL (strconv, QuoteLiteral), concatenations in messages, URLs, log lines and command arguments that are never run as a query, string literals, comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-023/",
	"languages": ["go"],
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

_db_strong := `Exec|ExecContext|Query|QueryContext|QueryRow|QueryRowContext|Prepare|PrepareContext|Queryx|QueryxContext|QueryRowx|QueryRowxContext|MustExec|MustExecContext|NamedExec|NamedExecContext|NamedQuery|NamedQueryContext|Raw`

_db_weak := `Select|SelectContext|Get|GetContext`

_db_open_strong := concat("", [`\.(?:`, _db_strong, `)\(`])

_db_open_weak := concat("", [`\.(?:`, _db_weak, `)\(`])

_lit := `"(?:[^"\\\n]|\\.)*"|\x60[^\x60\n]*\x60`

# A literal followed by + and a non-literal operand on the same line, or a
# literal ending the line with + (the operand opens the next line).
_concat_re := concat("", [`(`, _lit, `)\s*\+\s*([A-Za-z_(][^+]*)`])

_concat_eol_re := concat("", [`(`, _lit, `)\s*\+\s*$`])

_sql_kw := `(?i)\b(?:select|insert|update|delete|from|where|set|values|join|order\s+by|group\s+by|having|limit|union|returning)\b`

_sql_stmt := `(?i)\b(?:select\b[\s\S]+\bfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|merge\s+into|replace\s+into)\b`

_req_src := `\b(?:r|req|request)\.(?:FormValue|PostFormValue|PathValue)\(|\b(?:r|req|request)\.(?:URL\.(?:Query\(|RawQuery|Path)|Header\.Get\()|\bmux\.Vars\(|\bchi\.URLParam\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam|GetHeader)\(|\.ByName\(`

_strip_str(s) := regex.replace(s, `"(?:[^"\\\n]|\\.)*"|\x60[^\x60]*\x60`, `""`)

_backticks(s) := count(indexof_n(s, "\u0060"))

# A line that starts inside a raw string opened above is read with that
# string's closing quote balanced by a leading one.
_views(line) := {line} if _backticks(line) % 2 == 0

_views(line) := {line, concat("", ["\u0060", line])} if _backticks(line) % 2 == 1

_cont(l) if regex.match(`[+(,]\s*$`, l)

# The first line of the statement that line i continues: through lines that
# end with + ( or , and back to the opening of a raw string the view closes.
_raw_open(lines, i) := k if {
	cands := [j | some j in numbers.range(max([0, i - 12]), i); j < i; _backticks(lines[j]) % 2 == 1]
	count(cands) > 0
	k := max(cands)
}

_cont_start(lines, k) := s if {
	cands := [j |
		some j in numbers.range(max([0, k - 4]), k)
		j < k
		count([x | some x in numbers.range(j, k - 1); not _cont(lines[x])]) == 0
	]
	s := min(array.concat(cands, [k]))
}

_start(lines, i, view, line) := _cont_start(lines, i) if view == line

_start(lines, i, view, line) := _cont_start(lines, _raw_open(lines, i)) if view != line

# One concatenation: the literal, the operand and the text before the operand.
_hits(lines, i, line) := {[lit, op, view] |
	some view in _views(line)
	some m in regex.find_all_string_submatch_n(_concat_re, view, -1)
	lit := m[1]
	op := m[2]
}

_eol_hits(lines, i, line) := {[lit, op, view] |
	some view in _views(line)
	some m in regex.find_all_string_submatch_n(_concat_eol_re, view, 1)
	lit := m[1]
	j := helpers.next_code_index(lines, i, 2)
	nm := regex.find_all_string_submatch_n(`^\s*([A-Za-z_(][^+]*)`, lines[j], 1)
	count(nm) > 0
	op := nm[0][1]
}

_all_hits(lines, i, line) := _hits(lines, i, line) | _eol_hits(lines, i, line)

_lit_text(s) := concat("", [substring(l, 1, count(l) - 2) | some l in regex.find_n(_lit, s, -1)])

# The SQL text before the operand, across the statement's earlier lines.
_before(lines, start, i, view, lit) := concat("\n", array.concat([lines[j] | some j in numbers.range(start, i); j < i], [pre])) if {
	idx := indexof(view, lit)
	idx >= 0
	pre := substring(view, 0, idx + count(lit))
}

# The operand as one expression: a selector chain with its call arguments
# and an index, so the outer call's remaining arguments are not part of it.
_operand_re := `^[A-Za-z_][\w\.]*(?:\((?:[^()]|\([^()]*\))*\))?(?:\.[A-Za-z_]\w*(?:\((?:[^()]|\([^()]*\))*\))?)*(?:\[[^\]]*\])?`

_op(op) := m if {
	ms := regex.find_n(_operand_re, trim_space(op), 1)
	count(ms) > 0
	m := ms[0]
}

_op(op) := regex.replace(trim_space(op), `[\s,;)]+$`, "") if {
	count(regex.find_n(_operand_re, trim_space(op), 1)) == 0
}

_safe_op(op) if regex.match(`^(?:strconv\.|pq\.Quote|\w*\.?[Qq]uote\w*\(|\w*\.?[Ee]scape\w*\(|\w*\.?[Ss]anitiz\w*\(|len\()`, op)

# A call whose every argument is a literal (a subquery builder given its
# placeholder numbers) returns text fixed by the program; a request accessor
# given its key (c.Param("table")) is not one.
_safe_op(op) if {
	regex.match(`^[A-Za-z_][\w\.]*\(\s*(?:(?:"[^"]*"|\x60[^\x60]*\x60|\d+)\s*(?:,\s*(?:"[^"]*"|\x60[^\x60]*\x60|\d+)\s*)*)?\)?$`, op)
	not regex.match(_req_src, op)
}

_placeholder_op(op) if regex.match(`(?i)^(?:ph\w*|\w*placeholder\w*|p\d*|pn|pos|bind\w*)$`, op)

_placeholder_op(op) if regex.match(`(?i)^\w*(?:placeholder|bind|param|arg)\w*\(`, op)

# A parameter named for the bind argument it carries (slugArg, tenantParam).
_placeholder_op(op) if regex.match(`^(?:[a-z]\w*(?:Arg|Param|Placeholder|Ph)|arg|param)$`, op)

_const_name(content, op) if {
	regex.match(`^\w+$`, op)
	regex.match(concat("", [`(?m)^\s*(?:const\s+)?`, op, `\s*(?:string\s*)?=\s*["\x60]`]), content)
}

# The operand sits where SQL expects a literal: inside an open single quote,
# or after a comparison.
_value_pos(text, lit) if count(indexof_n(_lit_text(text), "'")) % 2 == 1

_value_pos(_, lit) if regex.match(`(?i)(?:[=<>]|\blike|\bilike|\bregexp|\brlike)\s*["]?\s*.$`, lit)

_value_hit(text, lit, op, content) if {
	_value_pos(text, lit)
	not _safe_op(op)
	not _placeholder_op(op)
	not _const_name(content, op)
}

_request_hit(_, _, op) if regex.match(_req_src, op)

_request_hit(lines, i, op) if {
	some t in helpers.tainted_names(lines, i, 25, _req_src)
	regex.match(concat("", [`\b`, t, `\b`]), op)
}

# Where the statement is run.
_assigned(l) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)*(?::=|\+=|=)`, l, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

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

_ctx(_, _, _, text, _, "strong") if regex.match(_db_open_strong, _strip_str(text))

_ctx(_, _, _, text, _, "weak") if {
	not regex.match(_db_open_strong, _strip_str(text))
	regex.match(_db_open_weak, _strip_str(text))
	regex.match(_sql_kw, _lit_text(text))
}

_ctx(lines, starts, start, text, stmt, "assigned") if {
	not regex.match(_db_open_strong, _strip_str(text))
	v := _assigned(lines[start])
	_assigned_sql(lines, starts, start, v, stmt)
}

_ctx(lines, _, start, _, stmt, "returned") if {
	regex.match(`^\s*return\b`, lines[start])
	regex.match(_sql_stmt, _lit_text(stmt))
}

_assigned_sql(lines, starts, start, v, _) if _reaches_db(lines, starts, start, v)

_assigned_sql(_, _, _, _, stmt) if regex.match(_sql_stmt, _lit_text(stmt))

_hit(_, _, _, text, lit, op, content) if _value_hit(text, lit, op, content)

_hit(lines, i, _, text, _, op, _) if {
	regex.match(_sql_kw, _lit_text(text))
	not _safe_op(op)
	_request_hit(lines, i, op)
}

_hit(lines, i, "strong", _, _, op, _) if {
	not _safe_op(op)
	_request_hit(lines, i, op)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?m)["\x60]\s*\+`, content)
	regex.match(`(?i)\b(?:select|insert|update|delete)\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	starts := [j | some j, l in lines; startswith(l, "func ")]
	some i, line in lines
	contains(line, "+")
	regex.match(`["\x60]\s*\+`, line)
	not helpers.is_comment_line(line)
	some h in _all_hits(lines, i, line)
	lit := h[0]
	op := _op(h[1])
	view := h[2]
	start := _start(lines, i, view, line)
	text := _before(lines, start, i, view, lit)
	stmt := concat("\n", [lines[j] | some j in numbers.range(start, i)])
	some kind in {"strong", "weak", "assigned", "returned"}
	_ctx(lines, starts, start, text, stmt, kind)
	_hit(lines, i, kind, text, lit, op, content)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL built by concatenation puts a value where SQL expects a literal (or a request value into the statement) and is run as a query; pass values as bind parameters ($1, ?) and pick identifiers from an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
