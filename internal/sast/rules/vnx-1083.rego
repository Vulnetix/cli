# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1083

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1083",
	"name": "Data Access from Outside Expected Data Manager Component",
	"description": "A Python presentation-layer module (a views, viewsets, routes, routers, controllers, handlers or endpoints module, or a file under a directory of one of those names) that goes around the data layer and reaches the database directly: it opens a DB-API connection (`sqlite3.connect`, `psycopg2.connect`, `pymysql.connect`, `MySQLdb.connect`, `mysql.connector.connect`, `cx_Oracle.connect`, `oracledb.connect`, `pyodbc.connect`, also through `import sqlite3 as sq` or `from sqlite3 import connect`), takes a raw cursor from Django's `connection`/`connections[...]`, runs hand-written SQL through Django's `Model.objects.raw(...)`, `.objects.extra(...)` or `RawSQL(...)`, or through SQLAlchemy's `db.session.execute(...)`/`db.engine.execute(...)` or a `text(...)` fragment passed to `filter`/`where`/`order_by`/`execute`. Raw SQL scattered across request handlers is where unparameterised queries and missing authorisation checks hide, because nothing central reviews it. One finding per access point. When the project also has a data manager module (models, repositories, dao, db ... by path), a handler's driver connect(), cursor(), objects.raw() and db.session/db.engine execute() of SQL text are reported by VNX-1057 on the same line, so this rule leaves them to it; it still reports them in projects with no such module, and always reports objects.extra(), RawSQL() and text() fragments. Not reported: the same calls in a repository, model, db or service module (the expected data manager), ORM queries in a view, other `connect()` calls (sockets, websockets, SSH, Redis), the text of comments, string literals and doctest (`>>>`) lines, and test files. Which module is the data manager is a project convention; this rule infers it from the file path only.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1083/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1083],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["data-access-outside-data-layer", "raw-sql", "cwe-1083"],
}

# Presentation-layer modules, by path.
_is_handler_module(path) if regex.match(`(^|/)(views|routes|routers?|controllers?|handlers|endpoints|api_views|viewsets)\.py$`, path)

_is_handler_module(path) if regex.match(`(^|/)(views|routes|routers|controllers|handlers|endpoints|viewsets)/[^/]+\.py$`, path)

_db_modules := `(?:sqlite3|psycopg2?|pymysql|MySQLdb|mysql\.connector|cx_Oracle|oracledb|pyodbc)`

# Raw SQL through an ORM: Django's raw()/extra()/RawSQL, SQLAlchemy's
# session/engine execute and text() fragments in a query.
_access_re := concat("", [
	`\b`, _db_modules, `\.connect\s*\(`,
	`|\bconnections?\s*(?:\[[^\]]+\])?\s*\.\s*cursor\s*\(`,
	`|\.objects\s*\.\s*(?:raw|extra)\s*\(`,
	`|\bRawSQL\s*\(`,
	`|\.(?:session|engine)\s*\.\s*execute\s*\(`,
	`|\.(?:filter|where|having|order_by|from_statement|execute)\s*\(\s*(?:sa\.|sqlalchemy\.)?text\s*\(`,
])

# `import sqlite3 as sq` makes `sq.connect(`; `from sqlite3 import connect [as c]`
# makes a bare `connect(` / `c(`.
_module_aliases(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^[ \t]*import[ \t]+`, _db_modules, `[ \t]+as[ \t]+(\w+)`]), content, -1)
}

_bare_connects(content) := {_bare_name(m) |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^[ \t]*from[ \t]+`, _db_modules, `[ \t]+import[ \t]+(?:[\w, \t]*,[ \t]*)?connect\b(?:[ \t]+as[ \t]+(\w+))?`]), content, -1)
}

_bare_name(m) := m[1] if m[1] != ""

_bare_name(m) := "connect" if m[1] == ""

_file_re(content) := concat("|", array.concat([_access_re], array.concat(
	[sprintf(`\b%s\.connect\s*\(`, [a]) | some a in _module_aliases(content)],
	[sprintf(`(?:^|[^\w.])%s\s*\(`, [b]) | some b in _bare_connects(content)],
)))

_strip_literals(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_strip_comment(line) := regex.replace(line, `#.*$`, "")

# ── Lines VNX-1057 reports ───────────────────────────────────────────────
# When the project has a data manager module (models/, repositories/, dao/,
# db/ ...), VNX-1057 reports a handler's driver connect(), cursor(),
# objects.raw() and db.session/db.engine execute() of SQL text, on the same
# line and for the same reason. Those lines are its to report.

_dm_re := `(?:^|/)(?:models|repositories|repository|repos|dao|daos|db|database|persistence|store|stores|crud|queries|dal|data_access)(?:\.py$|/)`

_has_dm if {
	some p, _ in input.file_contents
	endswith(p, ".py")
	not helpers.is_test_path(p)
	regex.match(_dm_re, p)
}

_handler_1057(path, _) if regex.match(`(?:^|/)(?:views?|routes?|router|routers|handlers?|controllers?|endpoints?|resolvers?|api|apis|blueprints?)(?:\.py$|/)`, path)

_handler_1057(_, content) if regex.match(`(?m)^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(|^\s*@api_view\s*\(|^\s*(?:async\s+)?def\s+\w+\s*\(\s*request\b`, content)

_access_1057 := `\b(?:sqlite3|psycopg2|psycopg|pymysql|MySQLdb|mysql\.connector|cx_Oracle|oracledb)\.connect\s*\(|\.cursor\s*\(\s*\)|\.objects\.raw\s*\(`

_session_sql_1057 := `\bdb\.(?:session|engine)\s*\.execute\s*\(\s*(?:text\s*\(|[rfbuRFBU]{0,2}(?:"""|'''|"|')\s*(?i:SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|WITH|CREATE|DROP|ALTER|TRUNCATE|PRAGMA)\b)`

_owned_by_1057(path, content, line) if {
	regex.match(_access_1057, _strip_literals(line))
	not regex.match(_dm_re, path)
	_handler_1057(path, content)
	_has_dm
}

_owned_by_1057(path, content, line) if {
	regex.match(_session_sql_1057, line)
	not regex.match(_dm_re, path)
	_handler_1057(path, content)
	_has_dm
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_is_handler_module(path)
	not helpers.is_test_path(path)
	re := _file_re(content)
	regex.match(concat("", ["(?m)", re]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(re, line)
	not helpers.is_comment_line(line)
	# doctest examples in a docstring, and the definition of a function named connect
	not regex.match(`^\s*(?:>>>|\.\.\.\s)`, line)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
	regex.match(re, _strip_comment(_strip_literals(line)))
	not _owned_by_1057(path, content, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Request handler reaches the database directly (raw connection, cursor or SQL) instead of going through the data layer; move the query into a repository or model method",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
