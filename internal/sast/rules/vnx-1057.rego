# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1057

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1057",
	"name": "Data Access Operations Outside of Expected Data Manager Component",
	"description": "A Python request-handling module performs raw database access although the project has a data manager component that should own it (CWE-1057). The handler module is one named or placed as a view, route, handler, controller, endpoint, resolver or API module (views.py, routes/, handlers.py, api/...) or one that declares routes (@app.route, @bp.get, @router.post, @api_view) or Django views (def name(request, ...)); the data manager component is another scanned file under a models, repositories, dao, db, database, persistence, store, crud or queries module. Raw access means: a DB-API driver connect() (sqlite3, psycopg2, pymysql, MySQLdb, mysql.connector, cx_Oracle), a .cursor() call, Django Model.objects.raw() or connection.cursor(), cursor.execute/executemany/executescript, and execute()/fetch()/fetchrow()/fetchval()/fetch_all()/fetch_one() (DB-API, asyncpg, databases) on a connection, db, session or engine handle whose argument is SQL text (a string starting with SELECT/INSERT/UPDATE/DELETE/WITH/..., sqlalchemy text(), or a name assigned such a string in the six lines above). Not reported: ORM queries (Model.objects.filter, session.query, select()), calls into the data manager's own functions, raw SQL inside the data manager modules themselves, projects with no data manager component, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1057/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1057],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["data-access-outside-mgr", "layering", "sql", "cwe-1057"],
}

_dm_re := `(?:^|/)(?:models|repositories|repository|repos|dao|daos|db|database|persistence|store|stores|crud|queries|dal|data_access)(?:\.py$|/)`

_handler_path_re := `(?:^|/)(?:views?|routes?|router|routers|handlers?|controllers?|endpoints?|resolvers?|api|apis|blueprints?)(?:\.py$|/)`

_route_re := `(?m)^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(|^\s*@api_view\s*\(|^\s*(?:async\s+)?def\s+\w+\s*\(\s*request\b`

_has_dm if {
	some p, _ in input.file_contents
	endswith(p, ".py")
	not helpers.is_test_path(p)
	regex.match(_dm_re, p)
}

_handler_module(path, _) if regex.match(_handler_path_re, path)

_handler_module(_, content) if regex.match(_route_re, content)

_gate := `\.(?:execute(?:many|script)?|fetch(?:row|val|all|one|_all|_one|_val)?|cursor|raw)\s*\(|\.connect\s*\(`

_sql_start := `(?i)(?:\btext\s*\(\s*)?(?:[rfbu]{0,2})(?:"""|'''|"|')\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|WITH|CREATE|DROP|ALTER|TRUNCATE|PRAGMA)\b|\btext\s*\(`

# Driver connect, cursor creation and Django raw(): raw access on the line.
# Calls are matched on the line with its string literals emptied, so a call
# written inside a string is not one.
_strip(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_raw_access(_, _, code) if regex.match(`\b(?:sqlite3|psycopg2|psycopg|pymysql|MySQLdb|mysql\.connector|cx_Oracle|oracledb)\.connect\s*\(`, code)

_raw_access(_, _, code) if regex.match(`\.cursor\s*\(\s*\)`, code)

_raw_access(_, _, code) if regex.match(`\.objects\.raw\s*\(`, code)

# cursor.execute(...) with any argument.
_raw_access(_, _, code) if regex.match(`\b(?:cursor|cur|c|csr)\.execute(?:many|script)?\s*\(`, code)

# execute() on a connection/db/session/engine handle with SQL text, on the
# same line or the next two.
_raw_access(lines, i, code) if {
	regex.match(_handle_exec_re, code)
	m := regex.find_n(_handle_exec_re, lines[i], 1)
	count(m) > 0
	rest := substring(lines[i], indexof(lines[i], m[0]) + count(m[0]), -1)
	_sql_arg(rest, lines, i)
}

_handle_exec_re := `(?:\b(?:conn|connection|con|db|database|session|engine|g\.db|self\.db|self\.conn|db\.session|db\.engine)|get_db\(\)|\))\s*\.(?:execute(?:many|script)?|fetch(?:row|val|all|one|_all|_one|_val)?)\s*\(`

_sql_arg(rest, _, _) if regex.match(concat("", [`^\s*(?:`, _sql_start, `)`]), rest)

# The argument is a name assigned SQL text in the six lines above:
# sql = "SELECT ..."; db.execute(sql, args).
_sql_arg(rest, lines, i) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*[,)]`, rest, 1)
	count(m) > 0
	re := concat("", [`^\s*`, m[0][1], `\s*=\s*(?:`, _sql_start, `)`])
	some k in numbers.range(max([0, i - 6]), i - 1)
	regex.match(re, lines[k])
}

_sql_arg(rest, lines, i) if {
	trim_space(rest) == ""
	k := helpers.next_code_index(lines, i, 2)
	regex.match(concat("", [`^\s*(?:`, _sql_start, `)`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	not regex.match(_dm_re, path)
	regex.match(_gate, content)
	_handler_module(path, content)
	_has_dm
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	_raw_access(lines, i, _strip(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Raw database access in a request handler while the project has a data manager component; move the query into the repository/model layer (CWE-1057)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
