# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1044

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1044",
	"name": "Architecture with Number of Horizontal Layers Outside of Expected Range",
	"description": "A layer count is not visible in one file, so this rule reports the concrete case of too few layers: the presentation layer (an HTTP controller, view, route handler or servlet) executing SQL against the database itself, with no data-access layer in between. That mixes request handling with query construction, which is where injectable queries and missing authorisation filters are introduced. Reported once per file, on the first such call: in Java, a file that is a Spring @Controller/@RestController, a JAX-RS @Path resource, an HttpServlet or a *Controller/*Servlet class and that calls createStatement/prepareStatement/prepareCall, a JDBC template or client (jdbcTemplate, namedParameterJdbcTemplate, jdbcClient ...) .query*/update/execute, or createNativeQuery, or executes a SQL literal; in Python, a Django/Flask/FastAPI view or route module (views.py, routes.py, views/ or routes/ directories, or @app.route/@bp.route/@router/@api_view handlers) that calls cursor/connection/db/session .execute*, get_db().execute, Model.objects.raw, pandas read_sql, or databases/asyncpg db/database/conn/pool .fetch_all/fetch_one/fetch/fetchrow/fetchval with SQL text; in JavaScript/TypeScript, a route or controller module (routes/ or controllers/ directories, *.controller.ts, a NestJS @Controller, or app/router.get/post/... handlers) that calls sequelize.query, knex.raw, Prisma $queryRaw/$executeRaw, or db/pool/connection/client/dataSource/manager/queryRunner .query/execute/run/all/get with SQL text (also a template literal opened on the call line with the SQL on the next line). A SQL keyword must be followed by whitespace, so a cache key such as 'select:' + id is not SQL. Parameterised and concatenated queries are both reported, because the defect is where the query is, not how it is built (the injection rules judge that). Not reported: SQL in repository, DAO, model or service files, ORM query builders and repository methods called from a controller, SQL text that is only logged or quoted, test code, migrations and comments.",
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
