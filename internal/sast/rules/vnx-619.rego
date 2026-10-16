# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_619

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-619",
	"name": "Database cursor opened in a function and never closed (Python DB-API)",
	"description": "Reports a Python DB-API cursor (sqlite3, psycopg2, MySQLdb/pymysql, Django connection.cursor(), get_db().cursor(), connections[\"replica\"].cursor(), await db.cursor()) assigned to a local variable inside a function and left open: the rest of the function never calls <cursor>.close(), never closes the connection it came from, does not use it as a context manager (with cur: / with closing(cur):), and does not return, yield or store it for a caller to close. An unclosed cursor holds its result set and server-side resources (a named PostgreSQL cursor, a MySQL unbuffered result) until garbage collection, and a pooled connection is handed to the next request with it still attached. Not reported: with conn.cursor() as cur, a close() in a finally block or later in the function, cur.close registered as a callback (ExitStack.callback, atexit) or wrapped in closing(cur), widget .cursor() calls in files importing PyQt/PySide/tkinter/wx, a cursor returned or yielded to the caller, a cursor stored on self, module-level scripts, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-619/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [619],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["dangling-db-cursor", "resource-leak", "cwe-619"],
}

_assign_re := `^(\s*)([A-Za-z_]\w*)\s*=\s*(?:await\s+)?((?:[A-Za-z_][\w\.]*\.)?([A-Za-z_]\w*)(?:\(\s*\)|\[[^\]]*\])?)\.cursor\(`

# GUI toolkits have a widget .cursor() that returns a mouse cursor, not a DB cursor.
_gui_module(content) if regex.match(`(?m)^\s*(from|import)\s+(PyQt\d|PySide\d?|qtpy|tkinter|wx)\b`, content)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_blank_or_comment(line) if trim_space(line) == ""

_blank_or_comment(line) if helpers.is_comment_line(line)

# Indentation of the nearest enclosing `def` above line i (within 200 lines).
_def_indent(lines, i, il) := di if {
	defs := [j |
		some j in numbers.range(max([0, i - 200]), i - 1)
		regex.match(`^\s*(async\s+)?def\s`, lines[j])
		_indent(lines[j]) < il
	]
	count(defs) > 0
	di := _indent(lines[max(defs)])
}

# The function body after line i: up to the first code line back at (or
# above) the def's indentation, capped at 150 lines.
_body_end(lines, i, di) := e if {
	last := min([count(lines) - 1, i + 150])
	ends := [k |
		some k in numbers.range(i + 1, last)
		not _blank_or_comment(lines[k])
		_indent(lines[k]) <= di
	]
	e := min(array.concat([last + 1], ends)) - 1
}

_released(body, v, _) if regex.match(concat("", [`\b`, v, `\.close\(\s*\)`]), body)

# stack.callback(cur.close), atexit.register(cur.close), closing(cur)
_released(body, v, _) if regex.match(concat("", [`(\(\s*`, v, `\.close\s*[,)]|\bclosing\(\s*`, v, `\s*\))`]), body)

_released(body, v, _) if regex.match(concat("", [`\bwith\s+(\w+\.)*(closing\(\s*)?`, v, `\s*[:)]`]), body)

_released(body, v, _) if regex.match(concat("", [`(?m)\b(return|yield(\s+from)?)\s+`, v, `\s*($|[,)\]#;])`]), body)

_released(body, v, _) if regex.match(concat("", [`(?m)\bself\.\w+\s*=\s*`, v, `\s*($|[,)#;])`]), body)

_released(body, _, conn) if regex.match(concat("", [`\b`, conn, `\.close\(\s*\)`]), body)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, ".cursor(")
	not _gui_module(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".cursor(")
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][2]
	conn := m[0][4]
	di := _def_indent(lines, i, count(m[0][1]))
	e := _body_end(lines, i, di)
	body := helpers.code_text(array.slice(lines, i + 1, e + 1))
	not _released(body, v, conn)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cursor '%s' is opened here and never closed in this function. Use 'with %s.cursor() as %s:' or close it in a finally block", [v, m[0][3], v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
