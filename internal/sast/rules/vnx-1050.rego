# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1050

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1050",
	"name": "Excessive Platform Resource Consumption within a Loop",
	"description": "Python code opens a new database connection, connection pool, SQLAlchemy engine, HTTP session/client, cloud SDK client, message-broker or SMTP/FTP connection on every iteration of a for or while loop, although nothing the constructor is given depends on the iteration, so the resource could be created once before the loop (CWE-1050). Reported constructors: sqlite3/psycopg2/psycopg/pymysql/MySQLdb/mysql.connector/pymssql/pyodbc/cx_Oracle/oracledb/asyncpg/aiomysql connect(), asyncpg/aiomysql create_pool(), create_engine/create_async_engine, MongoClient, redis.Redis/StrictRedis/from_url, requests.Session, httpx.Client/AsyncClient, aiohttp.ClientSession, urllib3.PoolManager, boto3.client/resource/Session, pika.BlockingConnection, smtplib.SMTP/SMTP_SSL and ftplib.FTP. Not reported: a constructor whose arguments use the loop variable or a name assigned inside the loop (a connection per host, shard or URI), retry and polling loops (the body breaks, sleeps or returns the resource, or the header names a retry/attempt counter), a resource created before the loop, open() of a file per iteration, loops written as examples inside a docstring, comments, string literals and test files. Deliberately not followed: modules imported under an alias (import psycopg2 as pg) or constructors imported by name (from sqlite3 import connect), and comprehensions.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1050/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1050],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-platform-resource-in-loop", "performance", "resource-management", "cwe-1050"],
}

_resource_re := `\b(?:(?:sqlite3|psycopg2|psycopg|pymysql|MySQLdb|mysql\.connector|pymssql|pyodbc|cx_Oracle|oracledb|asyncpg|aiomysql)\.connect|(?:asyncpg|aiomysql)\.create_pool|create_(?:async_)?engine|MongoClient|redis\.(?:Strict)?Redis|redis\.from_url|requests\.Session|httpx\.(?:Async)?Client|aiohttp\.ClientSession|urllib3\.PoolManager|boto3\.(?:client|resource|Session|session\.Session)|pika\.BlockingConnection|smtplib\.SMTP(?:_SSL)?|ftplib\.FTP)\s*\(`

_gate_re := `(?m)^\s*(?:async\s+)?(?:for|while)\b`

_loop_re := `^(\s*)(?:async\s+)?(for|while)\b(.*):\s*(?:#.*)?$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# Last line of the loop body: the line before the first code line at or below
# the header's indent, bounded to 80 lines.
_body_end(lines, i) := e if {
	k := _indent(lines[i])
	last := min([count(lines) - 1, i + 80])
	outs := [j |
		some j in numbers.range(i + 1, last)
		trim_space(lines[j]) != ""
		not helpers.is_comment_line(lines[j])
		_indent(lines[j]) <= k
	]
	e := _end_of(outs, last)
}

_end_of(outs, _) := outs[0] - 1 if count(outs) > 0

_end_of(outs, last) := last if count(outs) == 0

# Names that vary per iteration: the for-loop targets and every name assigned
# inside the body.
_loop_vars(header, kw) := {v |
	kw == "for"
	m := regex.find_all_string_submatch_n(`^\s*(?:async\s+)?for\s+(.+?)\s+in\s`, header, 1)
	some v in regex.find_n(`[A-Za-z_]\w*`, m[0][1], -1)
}

_body_vars(lines, i, e, j, jend) := _assigned_vars(lines, i, e, j, jend) | _bound_vars(lines, i, e, j, jend)

# Names assigned in the body, except on the lines of the call itself: its
# keyword arguments and the name it is bound to are not per-iteration inputs.
_assigned_vars(lines, i, e, j, jend) := {v |
	some k in numbers.range(i + 1, e)
	not _within(k, j, jend)
	v := helpers.assigned_first(lines[k])
}

_bound_vars(lines, i, e, j, jend) := {v |
	some k in numbers.range(i + 1, e)
	not _within(k, j, jend)
	m := regex.find_all_string_submatch_n(`^\s*(?:async\s+)?(?:for|with)\s+.*?(?:\bas\s+|for\s+)([A-Za-z_]\w*)`, lines[k], 1)
	v := m[0][1]
}

_within(k, j, jend) if {
	k >= j
	k <= jend
}

# Retry, first-success and polling loops make a fresh resource per attempt on
# purpose.
_retry_loop(header, _, _, _) if regex.match(`(?i)retr|attempt|tries`, header)

_retry_loop(_, lines, i, e) if {
	some j in numbers.range(i + 1, e)
	not helpers.is_comment_line(lines[j])
	regex.match(`^\s*break\b|\bsleep\s*\(`, lines[j])
}

# The call's argument text up to its closing parenthesis (two levels of
# nesting), across up to five more lines of the body.
_balanced_re := `^(?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_call_raw(lines, j, e) := raw if {
	m := regex.find_n(_resource_re, lines[j], 1)
	count(m) > 0
	start := indexof(lines[j], m[0]) + count(m[0])
	first := substring(lines[j], start, -1)
	last := min([e, j + 5])
	more := [lines[k] | last > j; some k in numbers.range(j + 1, last)]
	raw := concat("\n", array.concat([first], more))
}

_call_args(lines, j, e) := args if {
	raw := _call_raw(lines, j, e)
	b := regex.find_n(_balanced_re, raw, 1)
	count(b) > 0
	args := b[0]
} else := _call_raw(lines, j, e)

_uses_any(args, names) if {
	some v in names
	regex.match(concat("", [`\b`, v, `\b`]), args)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(_resource_re, content)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, header in lines
	m := regex.find_all_string_submatch_n(_loop_re, header, 1)
	count(m) > 0
	e := _body_end(lines, i)
	e > i
	some j in numbers.range(i + 1, e)
	code := _strip_strings(lines[j])
	regex.match(_resource_re, code)
	not helpers.is_comment_line(lines[j])
	not regex.match(`^\s*(return|yield)\b`, code)
	not _nested_def(lines, i, j)
	not _retry_loop(header, lines, i, e)
	not _in_docstring(lines, i)
	args := _call_args(lines, j, e)
	jend := j + count(indexof_n(args, "\n"))
	names := _loop_vars(header, m[0][2]) | _body_vars(lines, i, e, j, jend)
	not _uses_any(_strip_strings(args), names)
	finding := {
		"rule_id": metadata.id,
		"message": "A connection, client or session is created on every loop iteration with arguments that do not depend on the iteration; create it once before the loop (CWE-1050)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# The loop header sits inside a docstring or other triple-quoted string (an
# example in prose): an odd number of triple quotes in the 40 lines above.
_in_docstring(lines, i) if {
	i > 0
	n := sum([c |
		some k in numbers.range(max([0, i - 40]), i - 1)
		c := count(indexof_n(lines[k], "\"\"\"")) + count(indexof_n(lines[k], "'''"))
	])
	n % 2 == 1
}

_nested_def(lines, i, j) if {
	some k in numbers.range(i + 1, j)
	regex.match(`^\s*(async\s+)?def\s`, lines[k])
}
