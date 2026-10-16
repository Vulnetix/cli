# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1044

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1044",
	"name": "Architecture with Number of Horizontal Layers Outside of Expected Range",
	"description": "A layer count is not visible in one file, so this rule reports the concrete case of too few layers: the presentation layer (an HTTP controller, view, route handler or servlet) executing SQL against the database itself, with no data-access layer in between. That mixes request handling with query construction, which is where injectable queries and missing authorisation filters are introduced. Reported once per file, on the first such call: in Java, a file that is a Spring @Controller/@RestController, a JAX-RS @Path resource, an HttpServlet or a *Controller/*Servlet class and that calls createStatement/prepareStatement/prepareCall, a JDBC template or client (jdbcTemplate, namedParameterJdbcTemplate, jdbcClient ...) .query*/update/execute, or createNativeQuery, or executes a SQL literal; in Python, a Django/Flask/FastAPI view or route module (views.py, routes.py, views/ or routes/ directories, or @app.route/@bp.route/@router/@api_view handlers) that calls cursor/connection/db/session .execute*, get_db().execute, Model.objects.raw, pandas read_sql, or databases/asyncpg db/database/conn/pool .fetch_all/fetch_one/fetch/fetchrow/fetchval with SQL text; in JavaScript/TypeScript, a route or controller module (routes/ or controllers/ directories, *.controller.ts, a NestJS @Controller, or app/router.get/post/... handlers) that calls sequelize.query, knex.raw, Prisma $queryRaw/$executeRaw, or db/pool/connection/client/dataSource/manager/queryRunner .query/execute/run/all/get with SQL text (also a template literal opened on the call line with the SQL on the next line). A SQL keyword must be followed by whitespace, so a cache key such as 'select:' + id is not SQL. Parameterised and concatenated queries are both reported, because the defect is where the query is, not how it is built (the injection rules judge that). In a Python project that has a data manager module (models, repositories, dao, db ... by path), a handler file whose first direct SQL call is raw database access (driver connect(), cursor(), objects.raw(), cursor or db/session execute of SQL text) is reported by VNX-1057 on that line and every other, so this rule leaves the file to it. Not reported: SQL in repository, DAO, model or service files, ORM query builders and repository methods called from a controller, SQL text that is only logged or quoted, test code, migrations and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1044/",
	"languages": ["java", "python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1044],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["architecture", "layering", "data-access", "code-quality", "cwe-1044"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/(test|it)/|(^|/)(?:migrations?|seeds?|seeders)/`, path)

# ── Presentation-layer files ─────────────────────────────────────────────

_presentation(path, _, "java") if regex.match(`(?:Controller|Servlet)\.java$`, path)

_presentation(_, content, "java") if {
	some n in {"@RestController", "@Controller", "extends HttpServlet", "@Path("}
	contains(content, n)
}

_presentation(path, _, "py") if regex.match(`(?:^|/)(?:views|routes)(?:\.py$|/)`, path)

_presentation(_, content, "py") if regex.match(`(?m)^\s*@(?:\w+\.)?(?:route|get|post|put|patch|delete|api_view)\s*\(`, content)

_presentation(path, _, "js") if regex.match(`(?:^|/)(?:routes?|controllers?)(?:/|\.[jt]sx?$)|[Cc]ontroller\.[jt]sx?$`, path)

_presentation(_, content, "js") if contains(content, "@Controller(")

_presentation(_, content, "js") if regex.match(`\b(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\(\s*['"\x60/]`, content)

# ── SQL executed directly ────────────────────────────────────────────────

_needles := {
	"java": {"Statement(", "prepareCall(", "jdbc", "Jdbc", "createNativeQuery(", "execute"},
	"py": {"execute", ".raw(", "read_sql", ".fetch", ".iterate("},
	"js": {".query", ".raw(", "queryRaw", "executeRaw", ".execute(", ".run(", ".all(", ".get(", ".each(", ".exec("},
}

# A keyword followed by whitespace or the end of the line: 'select:' + id
# is a cache key, not SQL.
_sql_text := `['"\x60]\s*(?i:select|insert|update|delete|merge|with|create|drop|alter|truncate|replace|pragma)(?:\s|$)`

_sql_line := `^\s*(?i:select|insert|update|delete|merge|with|create|drop|alter|truncate|replace|pragma)(?:\s|$)`

_call_re := {
	"java": `\.(?:createStatement|prepareStatement|prepareCall)\s*\(|\b\w*[jJ]dbc\w*\.(?:query\w*|update|batchUpdate|execute|sql)\s*\(|\.createNativeQuery\s*\(`,
	"py": `\b(?:cur|curs|cursor|c|conn|con|connection|db|database|session|engine)\.(?:execute|executemany|executescript)\s*\(|\bget_db\(\)\.(?:execute|executemany|executescript)\s*\(|\.objects\.raw\s*\(|\b(?:pd|pandas)\.read_sql(?:_query)?\s*\(`,
	"js": `\bsequelize\.query\s*\(|\bknex\.raw\s*\(|\.\$(?:queryRaw|executeRaw)(?:Unsafe)?\s*[(\x60]`,
}

# Calls that are SQL only when their first argument is SQL text.
_text_head := {
	"java": `\.(?:execute|executeQuery|executeUpdate|executeLargeUpdate)\s*\(`,
	"js": `\b(?:db|pool|conn|connection|client|database|sql|sqlite|mysql|pg|dataSource|manager|entityManager|queryRunner)\.(?:query|execute|run|all|get|each|exec)\s*\(`,
	"py": `\b(?:db|database|conn|con|connection|pool)\.(?:fetch_all|fetch_one|fetch_val|fetch|fetchrow|fetchval|iterate)\s*\(`,
}

# String contents are blanked before a call is matched, so a call quoted in
# a message is not code.
_blank(line) := regex.replace(line, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`[^`]*`", "\"\"")

_sink(_, line, _, lang) if regex.match(_call_re[lang], _blank(line))

_sink(_, line, _, lang) if {
	regex.match(concat("", [_text_head[lang], `\s*`, _sql_text]), line)
	regex.match(concat("", [_text_head[lang], `\s*["'\x60]`]), _blank(line))
}

_sink(lines, line, i, lang) if {
	regex.match(concat("", [_text_head[lang], `\s*$`]), _blank(line))
	j := helpers.next_code_index(lines, i, 2)
	regex.match(concat("", [`^\s*`, _sql_text]), lines[j])
}

# A template literal or string opened at the end of the call line, the SQL
# starting on the next line.
_sink(lines, line, i, lang) if {
	regex.match(concat("", [_text_head[lang], "\\s*[\\x60\"']{1,3}\\s*$"]), line)
	j := helpers.next_code_index(lines, i, 2)
	regex.match(_sql_line, lines[j])
}

# ── Python lines VNX-1057 reports ────────────────────────────────────────
# When a Python project has a data manager module (models/, repositories/,
# dao/, db/ ...), VNX-1057 reports a handler's raw database access on every
# such line, saying the same thing: the query belongs in the data layer. A
# file whose first direct SQL call is one of those lines is its to report.

_dm_re := `(?:^|/)(?:models|repositories|repository|repos|dao|daos|db|database|persistence|store|stores|crud|queries|dal|data_access)(?:\.py$|/)`

_has_dm if {
	some p, _ in input.file_contents
	endswith(p, ".py")
	not helpers.is_test_path(p)
	regex.match(_dm_re, p)
}

_handler_1057(path, _) if regex.match(`(?:^|/)(?:views?|routes?|router|routers|handlers?|controllers?|endpoints?|resolvers?|api|apis|blueprints?)(?:\.py$|/)`, path)

_handler_1057(_, content) if regex.match(`(?m)^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(|^\s*@api_view\s*\(|^\s*(?:async\s+)?def\s+\w+\s*\(\s*request\b`, content)

_strip_1057(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_sql_start_1057 := `(?i)(?:\btext\s*\(\s*)?(?:[rfbu]{0,2})(?:"""|'''|"|')\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|WITH|CREATE|DROP|ALTER|TRUNCATE|PRAGMA)\b|\btext\s*\(`

_handle_exec_1057 := `(?:\b(?:conn|connection|con|db|database|session|engine|g\.db|self\.db|self\.conn|db\.session|db\.engine)|get_db\(\)|\))\s*\.(?:execute(?:many|script)?|fetch(?:row|val|all|one|_all|_one|_val)?)\s*\(`

_raw_1057(_, _, code) if regex.match(`\b(?:sqlite3|psycopg2|psycopg|pymysql|MySQLdb|mysql\.connector|cx_Oracle|oracledb)\.connect\s*\(|\.cursor\s*\(\s*\)|\.objects\.raw\s*\(|\b(?:cursor|cur|c|csr)\.execute(?:many|script)?\s*\(`, code)

_raw_1057(lines, i, code) if {
	regex.match(_handle_exec_1057, code)
	m := regex.find_n(_handle_exec_1057, lines[i], 1)
	count(m) > 0
	rest := substring(lines[i], indexof(lines[i], m[0]) + count(m[0]), -1)
	_sql_arg_1057(rest, lines, i)
}

_sql_arg_1057(rest, _, _) if regex.match(concat("", [`^\s*(?:`, _sql_start_1057, `)`]), rest)

_sql_arg_1057(rest, lines, i) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*[,)]`, rest, 1)
	count(m) > 0
	re := concat("", [`^\s*`, m[0][1], `\s*=\s*(?:`, _sql_start_1057, `)`])
	some k in numbers.range(max([0, i - 6]), i - 1)
	regex.match(re, lines[k])
}

_sql_arg_1057(rest, lines, i) if {
	trim_space(rest) == ""
	k := helpers.next_code_index(lines, i, 2)
	regex.match(concat("", [`^\s*(?:`, _sql_start_1057, `)`]), lines[k])
}

_owned_by_1057(path, content, lines, i, "py") if {
	not regex.match(_dm_re, path)
	_handler_1057(path, content)
	regex.match(`\.(?:execute(?:many|script)?|fetch(?:row|val|all|one|_all|_one|_val)?|cursor|raw)\s*\(|\.connect\s*\(`, lines[i])
	_raw_1057(lines, i, _strip_1057(lines[i]))
	_has_dm
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _needles[lang])
	not _is_test(path)
	_presentation(path, content, lang)
	lines := split(content, "\n")
	hits := {i |
		some i, line in lines
		_has_any(line, _needles[lang])
		not helpers.is_comment_line(line)
		_sink(lines, line, i, lang)
	}
	count(hits) > 0
	i := min(hits)
	not _owned_by_1057(path, content, lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL is executed directly in a controller, view or route handler, so the presentation layer talks to the database with no data-access layer in between; move the query into a repository or DAO and call that, which keeps query building and its authorisation filters in one reviewed place",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
