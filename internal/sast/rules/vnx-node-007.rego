package vulnetix.rules.vnx_node_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-007",
	"name": "Node.js SQL injection",
	"description": "An SQL statement built at run time is passed to a Node.js database call: .query/.execute (mysql, mysql2, pg, sequelize), .raw/.whereRaw/.orWhereRaw/.havingRaw/.orderByRaw/.joinRaw (knex), .where/.andWhere/.orWhere/.having query-builder conditions (TypeORM, MikroORM; a comparison fragment counts as SQL there), $queryRawUnsafe/$executeRawUnsafe (Prisma), .unsafe (postgres.js), or run/all/get/exec/each/prepare on a db/database/sqlite/conn/connection/client/pool/tx/trx receiver (sqlite3, better-sqlite3). The first argument (or the text/sql member of a query config object) is a template literal containing SQL (SELECT, INSERT INTO, UPDATE ... SET, DELETE FROM, WHERE, ORDER BY, VALUES) with a ${...} interpolation (also across line breaks), a string literal containing SQL joined with + to a value, or a variable assigned such a string within the previous 15 lines. Not reported: parameterised queries ($1, ?, :name with a values array), SQL without interpolation, tagged templates that parameterise (sql`...`, Prisma.sql`...`, prisma.$queryRaw`...`), interpolations that are numeric conversions (Number(), parseInt()), hashes (hash()), escapes (escape(), escapeId(), format()) or placeholder lists built with $${...} or '?' (also inline, ${ids.map(() => '?')}), and non-SQL strings, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-007/",
	"languages": ["node"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["sql-injection", "database", "mysql", "postgres"],
}

_is_js(path) if regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$`, path)

_sql_re := `(?i)\b(?:select\s+(?:[\w*"\x60$]|distinct|count)|insert\s+into|update\s+[\w"\x60.]+\s+set|delete\s+from|where\s|order\s+by|values\s*[($])`

_sink_re := `(?:\.(?:query|execute|raw|where|andWhere|orWhere|having|andHaving|orHaving|whereRaw|orWhereRaw|havingRaw|orderByRaw|joinRaw|groupByRaw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)|\b(?:db|database|sqlite|conn|connection|client|pool|tx|trx)\.(?:run|all|get|exec|each|prepare))\s*\(`

# Tagged templates parameterise, and complete string literals carry no code;
# both collapse to "" so a sink spelled inside one disappears.
_strip(line) := regex.replace(
	regex.replace(line, `[\w$.]+\x60[^\x60]*\x60`, `""`),
	`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\x60[^\x60$]*\x60`, `""`,
)

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	_sql_file(content)
	regex.match(_sink_re, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) <= 600
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _strip(line))
	m := regex.find_all_string_submatch_n(concat("", [_sink_re, `(.*)$`]), line, 1)
	count(m) > 0
	arg := regex.replace(_arg(lines, i, m[0][1]), `^\s*\{\s*(?:text|sql)\s*:\s*`, "")
	kw := _keyword_re(m[0][0])
	_built(lines, i, arg, kw)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL statement built with string concatenation or template-literal interpolation is passed to the database; use placeholders ($1, ?) with a values array, or a parameterising sql`` tag",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A file that spells SQL, or uses a knex *Raw fragment sink (whose fragments
# need not contain a keyword).
_sql_file(content) if regex.match(_sql_re, content)

_sql_file(content) if regex.match(`\.(?:where|orWhere|having|orderBy|join|groupBy)Raw\s*\(`, content)

# A query-builder condition (TypeORM, MikroORM) written as an interpolated
# template literal.
_sql_file(content) if regex.match(`\.(?:where|andWhere|orWhere|having|andHaving|orHaving)\s*\(\s*\x60[^\x60]*\$\{`, content)

# The argument text from the opening parenthesis onwards, with up to 10
# following lines so a template literal or a call broken across lines is
# read whole.
_arg(lines, i, rest) := concat("\n", array.concat([rest], array.slice(lines, i + 1, i + 11)))

# A template literal (not tagged) holding SQL and an unsafe interpolation.
_built(lines, i, arg, kw) if {
	t := regex.find_all_string_submatch_n(`^\s*\x60([^\x60]*)\x60`, arg, 1)
	count(t) > 0
	body := t[0][1]
	regex.match(kw, body)
	_unsafe_interpolation(lines, i, body)
}

# A string literal holding SQL joined with + to something else, in the first
# argument.
_built(_, _, arg, kw) if {
	first := regex.replace(regex.replace(arg, `^\s*\n`, ""), `\n[\s\S]*$`, "")
	regex.match(`^\s*(?:'[^']*'|"[^"]*")\s*\+|^[^,]*\+\s*(?:'[^']*'|"[^"]*")`, first)
	some lit in regex.find_all_string_submatch_n(`'[^']*'|"[^"]*"`, first, -1)
	regex.match(kw, lit[0])
}

# A variable assigned a built SQL string a few lines up.
_built(lines, i, arg, kw) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$]*)\s*[,)\n]`, arg, 1)
	count(m) > 0
	v := m[0][1]
	start := max([0, i - 15])
	some j in numbers.range(start, i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	helpers.assigned_first(prev) == v
	regex.match(kw, prev)
	_dynamic_assignment(lines, j, prev)
}

_dynamic_assignment(_, _, prev) if regex.match(`(?:'[^']*'|"[^"]*")\s*\+|\+\s*(?:'[^']*'|"[^"]*"|[\w$])`, prev)

_dynamic_assignment(lines, j, prev) if {
	t := regex.find_all_string_submatch_n(`=\s*\x60([^\x60]*)\x60?`, concat("\n", array.slice(lines, j, j + 10)), 1)
	count(t) > 0
	_unsafe_interpolation(lines, j, t[0][1])
}

_unsafe_interpolation(lines, i, body) if {
	some m in regex.find_all_string_submatch_n(`(?:^|[^$])\$\{([^}]*)\}`, body, -1)
	not _safe_expr(lines, i, trim_space(m[1]))
}

# An inline placeholder list: ${ids.map(() => "?").join(",")}.
_safe_expr(_, _, e) if regex.match(`['"]\?['"]|\x60\$`, e)

_safe_expr(_, _, e) if regex.match(`^(?:Number|parseInt|parseFloat|Math\.\w+)\s*\(|(?i)escape|\bformat\s*\(|\bhash\s*\(|^\d+$`, e)

# An ALL_CAPS constant (a table or column list fixed in the code).
_safe_expr(_, _, e) if regex.match(`^(?:[\w$]+\.)*[A-Z][A-Z0-9_]*$`, e)

# Arithmetic over variables each assigned from a numeric conversion nearby:
# `${page * 20}` after `const page = parseInt(...)`.
_safe_expr(lines, i, e) if {
	regex.match(`^[\w$\s*+\-/%()]+$`, e)
	ids := regex.find_all_string_submatch_n(`[A-Za-z_$][\w$]*`, e, -1)
	count(ids) > 0
	every id in ids {
		_numeric_var(lines, i, id[0])
	}
}

_numeric_var(lines, i, v) if {
	some j in numbers.range(max([0, i - 15]), i)
	helpers.assigned_first(lines[j]) == v
	regex.match(`=\s*(?:Number|parseInt|parseFloat|Math\.\w+)\s*\(`, lines[j])
}

# An identifier holding a placeholder list ($1, $2 / ?, ?) built nearby.
_safe_expr(lines, i, e) if {
	regex.match(`^[A-Za-z_$][\w$]*$`, e)
	some j in numbers.range(max([0, i - 15]), i)
	helpers.assigned_first(lines[j]) == e
	regex.match(`\$\$\{|['"]\?['"]|\?\s*,`, lines[j])
}

# knex *Raw fragment sinks take a bare SQL fragment ("name = ?"), so any
# literal counts as SQL there.
_keyword_re(call) := `.` if regex.match(`(?:where|having|orderBy|join|groupBy)Raw\s*\(`, call)

_keyword_re(call) := _sql_re if {
	not regex.match(`(?:where|having|orderBy|join|groupBy)Raw\s*\(`, call)
	not _condition_call(call)
}

# A query-builder condition (.where/.andWhere/.orWhere/.having) is a bare
# comparison fragment ("user.email = '...'"), so a comparison counts as SQL.
_keyword_re(call) := `(?i)[\w.\x60"\]]\s*(?:[<>!]?=|<>|<|>|\blike|\bin)\s*['"(:$?]` if _condition_call(call)

_condition_call(call) if regex.match(`^\.(?:where|andWhere|orWhere|having|andHaving|orHaving)\s*\(`, call)
