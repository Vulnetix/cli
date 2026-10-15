# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1089

import rego.v1

metadata := {
	"id": "VNX-1089",
	"name": "Large Data Table with Excessive Number of Indices",
	"description": "A table defined in the project's SQL files that carries more than 8 secondary indices. Counted: distinct index names from `CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] name ON [schema.]table` across every .sql file (so indices added by later migrations count, a re-run `IF NOT EXISTS` does not count twice, and an index removed by `DROP INDEX` does not count), plus inline MySQL `KEY`/`INDEX`/`UNIQUE KEY`/`FULLTEXT KEY` definitions inside the `CREATE TABLE` body and MySQL `ALTER TABLE t ADD [UNIQUE|FULLTEXT] INDEX|KEY name (...)` (net of `ALTER TABLE t DROP INDEX name`). Every index is maintained on every write, so a heavily indexed table that grows large slows inserts and updates and can be pushed into exhausting I/O. One finding per table, at its first `CREATE TABLE` line, or at its first index when the table is created elsewhere. Not counted: the primary key, UNIQUE/CHECK constraints, columns named key or index, and statements in `--` comments, in `/* */` comments (including multi-line blocks) or inside string literals. The order of migrations is not modelled: a name dropped anywhere is not counted. CWE-1089 is about large tables, and a table's row count cannot be known statically, so every table over the index threshold is reported; CISQ, which CWE-1089 cites, suggests 3 indices for a table of a million rows, and this rule uses 8 so that it points at the outliers.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1089/",
	"languages": ["sql"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1089],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-indices", "database-performance", "cwe-1089"],
}

_max_indices := 8

_max_table_lines := 300

_is_sql(path) if regex.match(`(?i)\.(sql|ddl|psql|pgsql)$`, path)

_ident := concat("", [`(?:[A-Za-z_][\w$]*|"[^"]+"|`, "`[^`]+`", `|\[[^\]]+\])`])

_qual_ident := concat("", [_ident, `(?:\s*\.\s*`, _ident, `)?`])

# CREATE INDEX ... ON table, possibly with ON on the next line (handled on the
# whole statement text below).
# Group 1: the index name (absent for an unnamed Postgres index); group 2: the table.
_create_index_re := concat("", [`(?is)^\s*create\s+(?:unique\s+)?(?:clustered\s+|nonclustered\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?(?:(`, _qual_ident, `)\s+)?on\s+(?:only\s+)?(`, _qual_ident, `)`])

_drop_index_re := concat("", [`(?i)^\s*drop\s+index\s+(?:concurrently\s+)?(?:if\s+exists\s+)?(`, _qual_ident, `)`])

_create_table_re := concat("", [`(?i)^\s*create\s+(?:temporary\s+|temp\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(`, _qual_ident, `)`])

# MySQL inline index definitions. `key VARCHAR(255)` is a column named key, so
# the parenthesised list must not start with a digit.
_inline_key_re := `(?i)^\s*(?:unique\s+|fulltext\s+|spatial\s+)?(?:key|index)\s+[^\s(]*\s*\(\s*[^\d\s)]|^\s*unique\s+(?:key|index)\s*\(`

# Normalised identifier: last dotted part, quotes removed, lower case.
_norm(name) := n if {
	parts := split(name, ".")
	last := trim_space(parts[count(parts) - 1])
	n := lower(trim(last, "\"`[] "))
}

_is_comment(line) if startswith(trim_space(line), "--")

_is_comment(line) if startswith(trim_space(line), "/*")

_is_comment(line) if startswith(trim_space(line), "*")

_sql_files[path] := split(content, "\n") if {
	some path, content in input.file_contents
	_is_sql(path)
	regex.match(`(?i)\b(?:index|key)\b`, content)
}

# Lines opening and closing /* */ comments, per file.
_block_starts[path] := [k | some k, l in lines; contains(l, "/*")] if some path, lines in _sql_files

_block_ends[path] := [k | some k, l in lines; contains(l, "*/")] if some path, lines in _sql_files

# Line k lies inside a /* */ comment opened on an earlier line and not yet closed.
_in_block(path, k) if {
	some s in _block_starts[path]
	s < k
	count([e | some e in _block_ends[path]; e >= s; e < k]) == 0
}

# The statement text at line i: the line itself when it already names the
# table, else the line plus the next two (ON on its own line).
_stmt(lines, i) := lines[i] if regex.match(`(?i)\son\s`, lines[i])

_stmt(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 2]))]) if {
	not regex.match(`(?i)\son\s`, lines[i])
}

# One entry per index: [table, index name, path, line index]. An unnamed index
# is named by its location.
_index_stmts := array.concat(array.concat(_create_index_entries, _alter_add_entries), _inline_entries)

_create_index_entries := [[t, n, path, i] |
	some path, lines in _sql_files
	some i, line in lines
	regex.match(`(?i)^\s*create\s+(?:unique\s+)?(?:\w+\s+)?index\b`, line)
	not _in_block(path, i)
	m := regex.find_all_string_submatch_n(_create_index_re, _stmt(lines, i), 1)
	count(m) == 1
	t := _norm(m[0][2])
	n := _index_name(m[0][1], path, i)
]

_alter_table_re := concat("", [`(?i)^\s*alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(`, _qual_ident, `)`])

_alter_add_re := concat("", [`(?i)\badd\s+(?:unique\s+|fulltext\s+|spatial\s+)?(?:index|key)\s*(`, _ident, `)?\s*\(`])

_alter_drop_re := concat("", [`(?i)\bdrop\s+(?:index|key)\s+(`, _ident, `)`])

# The lines of the ALTER TABLE statement starting at line i, to its `;`.
_alter_lines(lines, i) := [k | some k in numbers.range(i, e)] if {
	limit := min([count(lines) - 1, i + 30])
	ends := [k | some k in numbers.range(i, limit); regex.match(`;\s*(?:--.*)?$`, lines[k])]
	e := _first_or(ends, limit)
}

# [table, path, line index] of every live ALTER TABLE statement.
_alters := [[t, path, i] |
	some path, lines in _sql_files
	some i, line in lines
	regex.match(`(?i)^\s*alter\s+table\b`, line)
	not _in_block(path, i)
	m := regex.find_all_string_submatch_n(_alter_table_re, line, 1)
	count(m) == 1
	t := _norm(m[0][1])
]

# MySQL `ALTER TABLE t ADD [UNIQUE|FULLTEXT] INDEX|KEY name (cols)`.
_alter_add_entries := [[t, n, path, k] |
	some a in _alters
	t := a[0]
	path := a[1]
	lines := _sql_files[path]
	some k in _alter_lines(lines, a[2])
	not regex.match(`^\s*--`, lines[k])
	some m in regex.find_all_string_submatch_n(_alter_add_re, lines[k], -1)
	n := _index_name(m[1], path, k)
]

# Inline MySQL index definitions inside a CREATE TABLE body, named so a later
# DROP INDEX of one removes it.
_inline_entries := [[x[0], n, x[1], k] |
	some x in _tables
	lines := _sql_files[x[1]]
	some k in _inline_lines(lines, x[2])
	n := _inline_name(lines[k], x[1], k)
]

_inline_name_re := concat("", [`(?i)^\s*(?:unique\s+|fulltext\s+|spatial\s+)?(?:key|index)\s+(`, _ident, `)\s*\(`])

_inline_name(line, path, k) := _norm(m[0][1]) if {
	m := regex.find_all_string_submatch_n(_inline_name_re, line, 1)
	count(m) == 1
}

_inline_name(line, path, k) := sprintf("%s:%d", [path, k]) if {
	count(regex.find_all_string_submatch_n(_inline_name_re, line, 1)) == 0
}

_index_name(raw, path, i) := _norm(raw) if raw != ""

_index_name("", path, i) := sprintf("%s:%d", [path, i])

_dropped := {_norm(m[0][1]) |
	some path, lines in _sql_files
	some i, line in lines
	regex.match(`(?i)^\s*drop\s+index\b`, line)
	not _in_block(path, i)
	m := regex.find_all_string_submatch_n(_drop_index_re, line, 1)
	count(m) == 1
} | {_norm(m[1]) |
	some a in _alters
	lines := _sql_files[a[1]]
	some k in _alter_lines(lines, a[2])
	not regex.match(`^\s*--`, lines[k])
	some m in regex.find_all_string_submatch_n(_alter_drop_re, lines[k], -1)
}

# One entry per CREATE TABLE: [table, path, line index].
_tables := [[t, path, i] |
	some path, lines in _sql_files
	some i, line in lines
	regex.match(`(?i)^\s*create\s+(?:\w+\s+)*table\b`, line)
	not _in_block(path, i)
	m := regex.find_all_string_submatch_n(_create_table_re, line, 1)
	count(m) == 1
	t := _norm(m[0][1])
]

# Body lines of the CREATE TABLE at line i that define an inline index.
_inline_lines(lines, i) := [k |
	some k in numbers.range(i + 1, e)
	not _is_comment(lines[k])
	regex.match(_inline_key_re, lines[k])
] if {
	limit := min([count(lines) - 1, i + _max_table_lines])
	ends := [k | some k in numbers.range(i, limit); regex.match(`;\s*(?:--.*)?$`, lines[k])]
	e := _first_or(ends, limit)
}

_first_or(xs, d) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

# Distinct live index names per table: re-running `CREATE INDEX IF NOT EXISTS`
# in a later migration does not add an index, and `DROP INDEX` (or MySQL's
# `ALTER TABLE ... DROP INDEX`) removes one.
_live := {[s[0], s[1]] | some s in _index_stmts; not s[1] in _dropped}

_count_by[t] := c if {
	some t in {p[0] | some p in _live}
	c := count({p[1] | some p in _live; p[0] == t})
}

_crowded := {t | some t, c in _count_by; c > _max_indices}

_message(t) := sprintf("Table %s has %d secondary indices (limit %d); every index is updated on every write, so drop the ones no query needs", [t, _count_by[t], _max_indices])

# Where to report a crowded table: its first CREATE TABLE, else its first index.
_anchor(t) := a if {
	defs := sort([[x[1], x[2]] | some x in _tables; x[0] == t])
	count(defs) > 0
	a := defs[0]
}

_anchor(t) := a if {
	count([1 | some x in _tables; x[0] == t]) == 0
	firsts := sort([[s[2], s[3]] | some s in _index_stmts; s[0] == t])
	a := firsts[0]
}

findings contains finding if {
	some t in _crowded
	a := _anchor(t)
	path := a[0]
	i := a[1]
	finding := {
		"rule_id": metadata.id,
		"message": _message(t),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": _sql_files[path][i],
	}
}
