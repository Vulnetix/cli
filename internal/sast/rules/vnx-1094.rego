# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1094

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1094",
	"name": "Excessive Index Range Scan for a Data Resource",
	"description": "Python DB-API code runs a SELECT whose WHERE clause is an open range over caller-supplied bounds (BETWEEN %s AND %s, or a column compared with <, <=, > or >= against a placeholder: %s, ?, :name, %(name)s, $1) with no LIMIT, TOP, FETCH FIRST or aggregate, and then loads the whole result with fetchall(). The number of rows the index range scan covers, and the memory the result takes, is decided by whoever chooses the bounds, so a wide range turns one request into a scan of the table. Reported: the cursor.execute(...) line when the SQL text (inline, in the five lines above, or, when execute's first argument is a variable, from that variable's assignment up to 30 lines above, which covers long triple-quoted SQL) has that shape and fetchall() follows within eight lines. Not reported: queries with LIMIT/TOP/FETCH FIRST or COUNT/SUM/MIN/MAX/AVG, equality predicates, results read with fetchone(), fetchmany() or iterated in batches, ORM queries, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1094/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1094],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["sql", "performance", "resource-consumption", "cwe-1094"],
}

_placeholder := `(?:%s|\?|:[A-Za-z_]\w*|%\(\w+\)s|\$\d+)`

_range_re := concat("", [
	`(?is)\bselect\b.+?\bwhere\b.*?(?:\bbetween\s+`, _placeholder, `\s+and\s+`, _placeholder,
	`|\w\s*(?:<|<=|>|>=)\s*`, _placeholder, `)`,
])

_bounded_re := `(?i)\blimit\b|\btop\s*\(?\s*\d|\bfetch\s+(first|next)\b|\b(count|sum|min|max|avg)\s*\(`

# The SQL text for the execute call at line i: the call itself and the few
# lines above it where a query variable is normally assigned, up to (not
# including) an earlier execute.
_sql_window(lines, i) := txt if {
	start := max([0, i - 5])
	prev := [k | some k in numbers.range(start, i - 1); i > 0; contains(lines[k], ".execute(")]
	s := max(array.concat([start - 1], prev)) + 1
	end := min([count(lines) - 1, i + 6])
	stop := [k | some k in numbers.range(i + 1, end); i + 1 <= end; regex.match(`\)\s*$|^\s*\w[\w\.]*\s*=`, lines[k])]
	e := min(array.concat([end], stop))
	txt := concat("\n", [l | some k in numbers.range(s, e); l := lines[k]; not helpers.is_comment_line(l)])
}

# execute(sql, ...) where sql was assigned further up (a long triple-quoted
# query): the text from that assignment, at most 30 lines above, to the call.
_var_window(lines, i) := txt if {
	m := regex.find_all_string_submatch_n(`\.execute\(\s*([A-Za-z_]\w*)\s*[,)]`, lines[i], 1)
	count(m) > 0
	name := m[0][1]
	start := max([0, i - 30])
	assigns := [k | some k in numbers.range(start, i - 1); i > 0; regex.match(concat("", [`^\s*`, name, `\s*=[^=]`]), lines[k])]
	count(assigns) > 0
	s := max(assigns)
	txt := concat("\n", [l | some k in numbers.range(s, i); l := lines[k]; not helpers.is_comment_line(l)])
}

_fetches_all(lines, i) if {
	end := min([count(lines) - 1, i + 8])
	some k in numbers.range(i, end)
	contains(lines[k], ".fetchall()")
	not helpers.is_comment_line(lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, ".fetchall()")
	contains(content, ".execute(")
	regex.match(`(?i)\bwhere\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".execute(")
	not helpers.is_comment_line(line)
	_fetches_all(lines, i)
	some w in ({w1 | w1 := _sql_window(lines, i)} | {w2 | w2 := _var_window(lines, i)})
	regex.match(_range_re, w)
	not regex.match(_bounded_re, w)
	finding := {
		"rule_id": metadata.id,
		"message": "SELECT over a caller-chosen range with no LIMIT is read in full with fetchall(); bound the range, add LIMIT/pagination or stream with fetchmany()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
