# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1049

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1049",
	"name": "Excessive Data Query Operations in a Large Data Table",
	"description": "A single SQL SELECT statement written in Python, Java or JavaScript/TypeScript source combines five or more join and sub-query operations (JOIN clauses of any kind plus parenthesised SELECT sub-queries), the CWE-1049 shape of a query whose cost grows with every table it touches and degrades badly once those tables are large. The statement is read from the string literal it is written in: a triple-quoted Python string, a Java text block or a JavaScript template literal up to its closing delimiter, or adjacent/concatenated string literals up to the end of the statement or call. A literal holding a script of several statements separated by semicolons is judged statement by statement, and a statement counts only when it reads FROM a table, so a docstring that begins with \"Select\" and mentions joining is not SQL; an interpolated table name (join {table}, JOIN ${t}, join %s) counts as a join. The report is on the line where the query starts. Not reported: queries with four or fewer joins and sub-queries, several small queries in a row (each statement is counted on its own), str.join/path.join calls, SQL in comments, and query builders or ORM chains whose joins are not written as SQL text. Whether the tables really are large is not known to the rule; treat a finding as a prompt to check the query plan, add indexes or a materialised view, or split the query.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1049/",
	"languages": ["python", "java", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1049],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-data-query", "sql", "performance", "cwe-1049"],
}

_exts := [".py", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

_threshold := 5

_span := 40

# Multi-line literal delimiters: Python triple quotes, Java text blocks and
# JavaScript template literals.
_delims := ["\"\"\"", "'''", "`"]

# A JOIN keyword followed by a table, not str.join( or path.join(.
_join_re := "(?i)(?:^|[^.\\w])join\\s+[\\w\"`\\[({$%]"

_subq_re := `(?i)\(\s*select\b`

_starts_select(s) if regex.match(`(?i)^\s*(select|with)\s`, s)

# Multi-line literal opened on line i: exactly one delimiter on the line, and
# the literal's text (rest of the line, or the next line) begins the query.
_ml_delims(lines, i) := {d |
	some d in _delims
	count(indexof_n(lines[i], d)) == 1
	rest := substring(lines[i], indexof(lines[i], d) + count(d), -1)
	_ml_begins(lines, i, rest)
}

_ml_begins(_, _, rest) if _starts_select(rest)

_ml_begins(lines, i, rest) if {
	trim_space(rest) == ""
	i + 1 < count(lines)
	_starts_select(lines[i + 1])
}

_ml_end(lines, i, d) := e if {
	last := min([count(lines) - 1, i + _span])
	ends := [j | some j in numbers.range(i + 1, last); contains(lines[j], d)]
	e := min(array.concat([last], ends))
}

# Adjacent or concatenated literals starting with SELECT on line i.
_cat_start(line) if {
	regex.match(`(?i)["']\s*select\s`, line)
	not _has_single_delim(line)
}

_has_single_delim(line) if {
	some d in _delims
	count(indexof_n(line, d)) == 1
}

_continues(line) if regex.match(`(\+|\\|\(|,)\s*$`, trim_space(line))

_continues(line) if count(indexof_n(line, "(")) > count(indexof_n(line, ")"))

# Python implicit concatenation and a leading `+` on the next line.
_continued(lines, i) if _continues(lines[i])

_continued(lines, i) if {
	i + 1 < count(lines)
	regex.match(`^\s*(["']|\+)`, lines[i + 1])
}

_cat_end(lines, i) := i if not _continued(lines, i)

_cat_end(lines, i) := e if {
	_continued(lines, i)
	last := min([count(lines) - 1, i + _span])
	ends := [j |
		some j in numbers.range(i + 1, last)
		regex.match(`(;|\))\s*:?$`, trim_space(lines[j]))
	]
	e := min(array.concat([last], ends))
}

_query_text(lines, i, e) := concat("\n", [l |
	some j in numbers.range(i, e)
	l := lines[j]
	not helpers.is_comment_line(l)
])

# Joins and sub-queries of the largest statement in the literal: a script of
# several statements separated by ";" is judged statement by statement, and a
# statement only counts when it reads FROM a table (prose that starts with
# "Select" and mentions "join" is not SQL).
_ops(txt) := max([n |
	some stmt in split(txt, ";")
	n := _stmt_ops(stmt)
])

_stmt_ops(stmt) := count(regex.find_n(_join_re, stmt, -1)) + count(regex.find_n(_subq_re, stmt, -1)) if {
	regex.match(`(?i)\bfrom\s+[\w"\x60\[({$%]`, stmt)
} else := 0

_queries_at(lines, i) := {txt |
	some d in _ml_delims(lines, i)
	txt := _query_text(lines, i, _ml_end(lines, i, d))
} if {
	_has_single_delim(lines[i])
}

_queries_at(lines, i) := {_query_text(lines, i, _cat_end(lines, i))} if {
	_cat_start(lines[i])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`(?i)\bjoin\s`, content)
	regex.match(`(?i)\bselect\s`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)(select|with)\s|["'\x60]\s*$`, line)
	not helpers.is_comment_line(line)
	some txt in _queries_at(lines, i)
	n := _ops(txt)
	n >= _threshold
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL query combines %d joins and sub-queries; on large tables this is an excessive data query (CWE-1049)", [n]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
