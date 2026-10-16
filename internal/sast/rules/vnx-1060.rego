# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1060

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1060",
	"name": "Excessive Number of Inefficient Server-Side Data Accesses",
	"description": "Python N+1 query: a database query (DB-API cursor/connection .execute(), SQLAlchemy session.query()/Model.query.get(), Django Model.objects.get()/filter(), asyncpg conn.fetch()/fetchrow()/fetchval()) issued inside the body of a for/async for loop, or inside a list/dict/set comprehension, with the loop variable, or a name the loop body assigns from it, in the query's arguments. Each iteration makes one more round trip to the database where one batched query (WHERE id IN (...), select_related/joinedload, executemany) would do. Not reported: a query inside a loop that does not use the loop variable (a retry loop), a loop that hands each chunk to one IN/ANY/__in/in_() query, a loop whose variable is the statement being executed (a schema or migration runner), executemany(), a query after the loop has ended, queries built and run once from a list the loop collected, and the pattern in strings or comments. Loops are recognised by indentation within 25 lines above the query; queries reached through helper functions are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1060/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1060],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["inefficient-server-side-access", "n-plus-one", "performance", "python", "cwe-1060"],
}

# A query call: a DB-API execute on a cursor/connection-like receiver, an ORM
# lookup. executemany( is the batched form and does not match.
_q_re := `(?:\b(?:cursor|cur|cr|conn|connection|con|db|session|sess)\.execute\(|\.objects\.(?:get|filter|exclude|get_or_create)\(|\bsession\.(?:query|get|scalar|scalars)\(|\.query\.(?:get|filter_by|filter|get_or_404)\(|\b(?:conn|connection|con|db|pool)\.(?:fetchrow|fetchval|fetch)\()`

_for_re := `^(\s*)(?:async\s+)?for\s+\(?\s*([A-Za-z_][\w\s,()]*?)\s*\)?\s+in\s+.+:\s*(?:#.*)?$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_blank_or_comment(line) if trim_space(line) == ""

_blank_or_comment(line) if helpers.is_comment_line(line)

# The call text after the query token, across the lines of a call that does
# not close on its own line.
_call_text(lines, i) := t if {
	line := lines[i]
	count(indexof_n(line, "(")) <= count(indexof_n(line, ")"))
	t := line
}

_call_text(lines, i) := t if {
	line := lines[i]
	count(indexof_n(line, "(")) > count(indexof_n(line, ")"))
	t := concat("\n", array.slice(lines, i, min([count(lines), i + 5])))
}

_tail(txt) := concat("", array.slice(parts, 1, count(parts))) if {
	parts := regex.split(_q_re, txt)
	count(parts) > 1
}

# Names bound by the loop header at line k.
_loop_vars(header) := {v |
	m := regex.find_all_string_submatch_n(_for_re, header, 1)
	some raw in split(m[0][2], ",")
	v := trim(raw, " \t()")
	regex.match(`^[A-Za-z_]\w*$`, v)
	v != "_"
}

# The loop that encloses line i: its header is shallower, and no line between
# them is at or above the header's indentation (the loop has not ended).
_enclosing_loop(lines, i) := k if {
	ii := _indent(lines[i])
	some k in numbers.range(max([0, i - 25]), i - 1)
	regex.match(_for_re, lines[k])
	ik := _indent(lines[k])
	ik < ii
	not _closed(lines, k, i, ik)
}

_closed(lines, k, i, ik) if {
	k + 1 <= i - 1
	some m in helpers.span(k + 1, i - 1)
	not _blank_or_comment(lines[m])
	_indent(lines[m]) <= ik
}

_uses(txt, v) if regex.match(concat("", [`\b`, v, `\b`]), txt)

# A batched query: the loop hands a whole chunk to one IN/ANY lookup.
_batched(tail) if regex.match(`(?i)(?:\bIN\s*(?:%s|\?|:\w|\$\d|\(\s*(?:%s|\?|:|\$))|__in\s*=|\.in_\s*\(|=\s*ANY\s*\()`, tail)

# Names the loop body derives from the loop variable before the query:
# `invoice_id = inv["id"]`.
_derived(lines, k, i, vars) := {d |
	k + 1 <= i - 1
	some m in helpers.span(k + 1, i - 1)
	mm := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*=\s*([^=].*)$`, lines[m], 1)
	count(mm) > 0
	some v in vars
	_uses(mm[0][2], v)
	d := mm[0][1]
}

# The loop variable is the statement itself (a schema or migration runner).
_runs_statement(tail, vars) if {
	some v in vars
	regex.match(concat("", [`^\s*`, v, `\s*[,)]`]), tail)
}

# Query in a loop body, keyed by the loop variable or a name derived from it.
_n_plus_one(lines, i, tail) if {
	k := _enclosing_loop(lines, i)
	vars := _loop_vars(lines[k])
	not _batched(tail)
	not _runs_statement(tail, vars)
	names := vars | _derived(lines, k, i, vars)
	some v in names
	_uses(tail, v)
}

# Query inside a comprehension: [Model.query.get(x) for x in ids]
_n_plus_one(_, _, tail) if {
	not _batched(tail)
	m := regex.find_all_string_submatch_n(`^(.*?)\bfor\s+([A-Za-z_]\w*)\s+in\b`, tail, 1)
	count(m) > 0
	_uses(m[0][1], m[0][2])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "for ")
	regex.match(_q_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_q_re, line)
	not helpers.is_comment_line(line)
	tail := _tail(_call_text(lines, i))
	_n_plus_one(lines, i, tail)
	finding := {
		"rule_id": metadata.id,
		"message": "Database query issued once per loop iteration (N+1): batch it into one query (WHERE id IN (...), select_related/joinedload, executemany)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
