package vulnetix.rules.vnx_php_011

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-011",
	"name": "PHP SQL injection via string concatenation",
	"description": "User input is concatenated or interpolated into the SQL text handed to a query API. Sinks: mysql_query(), mysqli_query(), mysqli_multi_query(), mysqli_real_query(), pg_query(), pg_send_query(), sqlite_query(), the ->query(), ->exec(), ->multi_query(), ->real_query() and ->prepare() methods (PDO, mysqli, SQLite3), WordPress $wpdb->get_results()/get_row()/get_var()/get_col(), Laravel DB::select/insert/update/delete/statement/unprepared/raw() and the ->whereRaw()/selectRaw()/orderByRaw()/havingRaw()/groupByRaw() builders. User input is a $_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES element, a client-controlled $_SERVER key (HTTP_* headers, PHP_SELF, REQUEST_URI, QUERY_STRING, PATH_INFO, PHP_AUTH_*; not REMOTE_ADDR or SCRIPT_NAME), or a Laravel $request->input()/get()/query()/post()/cookie()/header() or request('x') value, appearing in the call's arguments (on the call line or the next two lines of a call broken across lines), through a variable assigned from it within the 40 lines above, or through a query string built from such a variable (assigned or appended with .=, including a concatenation continued over up to five lines) within the 25 lines above the call. Not reported: placeholders with bound parameters (prepare/execute, bind_param, pg_query_params, DB::select with bindings), values passed through intval()/(int)/floatval(), mysqli_real_escape_string(), pg_escape_string/literal(), addslashes() or ->quote(), a value checked with is_numeric()/ctype_digit()/is_int() or a digits-only preg_match() in the same window, user input inside a single-quoted literal (which PHP does not interpolate), constant queries, and the call inside a comment or a string. Escaping that is ineffective because the value is not quoted in the SQL (a numeric context) is deliberately not distinguished.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-011/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["sql-injection", "injection", "php"],
}

_proc_re := `(?i)\b(mysql_query|mysqli_query|mysqli_multi_query|mysqli_real_query|pg_query|pg_send_query|sqlite_query)\s*\(`

# Methods and builders whose first argument is the SQL; later arguments are
# bindings or fetch modes and are not SQL text.
_method_re := `(?i)(->(query|exec|multi_query|real_query|prepare|get_results|get_row|get_var|get_col)|\bDB::(select|insert|update|delete|statement|unprepared|raw)|(->|::)(whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw))\s*\(`

_sink_re := concat("|", [_proc_re, _method_re])

_gate_re := `(?i)(mysqli?_|pg_(send_)?query|sqlite_query|->(query|exec|multi_query|real_query|prepare|\w+Raw)\s*\(|DB::)`

# $_SERVER counts only for the keys a client controls (request headers, the
# URL, the HTTP auth credentials), not REMOTE_ADDR or DOCUMENT_ROOT.
_source_re := `\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"]?(HTTP_\w+|PHP_SELF|REQUEST_URI|QUERY_STRING|PATH_INFO|ORIG_PATH_INFO|PHP_AUTH_USER|PHP_AUTH_PW)\b|\$request->(input|get|query|post|cookie|header)\s*\(|\brequest\s*\(\s*['"]`

_sanitizer_re := `(?i)(\(\s*(int|integer|float|double|bool)\s*\)\s*\$[\w\[\]'"\->]+|\b(intval|floatval|boolval|abs|mysqli_real_escape_string|mysql_real_escape_string|mysql_escape_string|pg_escape_string|pg_escape_literal|pg_escape_identifier|sqlite_escape_string|addslashes|count|sizeof|strlen|is_numeric|ctype_digit|md5|sha1|password_hash|json_encode)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|->(quote|escape|real_escape_string|escape_string)\s*\((?:[^()]|\([^()]*\))*\))`

_lit_re := `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

# Code with sanitiser calls removed and single-quoted literals emptied (PHP
# does not interpolate them). Literals are tokenised left to right so a single
# quote inside a double-quoted SQL string stays part of that string.
_clean(text) := out if {
	# Array keys are unquoted first so $_SERVER['HTTP_X'] keeps its key.
	s := regex.replace(regex.replace(text, _sanitizer_re, "0"), `\[\s*'(\w+)'\s*\]`, "[$1]")
	out := strings.replace_n(
		{lit: `''` | some lit in regex.find_n(_lit_re, s, -1); startswith(lit, "'")},
		s,
	)
}

_refs(text, v) if regex.match(concat("", [`\$`, v, `\b|\{\$`, v, `\b`]), text)

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*\.?=[^=]`, line, 1)
	v := m[0][1]
}

_rhs(line) := r if {
	parts := regex.split(`\.?=`, line)
	r := concat("=", array.slice(parts, 1, count(parts)))
}

# Level 0: variables assigned straight from user input, not through a
# sanitiser, in the window above the sink.
_level0(lines, i) := {v |
	some j in numbers.range(max([0, i - 40]), i - 1)
	prev := lines[j]
	regex.match(_source_re, prev)
	not helpers.is_comment_line(prev)
	v := _assigned(prev)
	regex.match(_source_re, _clean(_rhs(prev)))
	not _resanitised(lines, i, j, v)
	not _digit_checked(lines, i, j, v, _rhs(prev))
}

# A numeric validation of the value (or of the request element it was read
# from) in the window: is_numeric()/ctype_digit()/is_int() or a preg_match()
# with a digits-only pattern.
_squash(s) := regex.replace(s, `\s+`, "")

_digit_checked(lines, i, j, v, rhs) if {
	w := _squash(helpers.code_window(lines, i, 40, 0))
	some expr in _checked_exprs(v, rhs)
	some f in ["is_numeric(", "ctype_digit(", "is_int("]
	contains(w, concat("", [f, expr]))
}

_digit_checked(lines, i, j, v, rhs) if {
	w := _squash(helpers.code_window(lines, i, 40, 0))
	some m in regex.find_all_string_submatch_n(`preg_match\(['"][^'"]*\\d[^'"]*['"],(\$[^,)]*)\)`, w, -1)
	some expr in _checked_exprs(v, rhs)
	m[1] == expr
}

_checked_exprs(v, rhs) := {concat("", ["$", v])} | {e |
	some m in regex.find_n(`\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]`, rhs, 1)
	e := _squash(m)
}

_resanitised(lines, i, j, v) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	_assigned(lines[k]) == v
	not regex.match(concat("", [`\$`, v, `\b`]), _clean(_rhs(lines[k])))
}

# Level 1: variables (a query string, typically) built from level-0 values or
# user input in the same window.
_level1(lines, i, l0) := {v |
	some j in numbers.range(max([0, i - 25]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	v := _assigned(prev)
	not l0[v]
	rhs := _clean(_stmt_rhs(lines, j, i))
	some u in l0
	_refs(rhs, u)
	not _resanitised(lines, i, j, v)
}

# The right-hand side of an assignment, with the continuation lines of a
# statement broken across lines (up to five, never reaching the sink line).
_stmt_rhs(lines, j, _) := _rhs(lines[j]) if contains(lines[j], ";")

_stmt_rhs(lines, j, i) := concat("\n", array.concat([_rhs(lines[j])], cont)) if {
	not contains(lines[j], ";")
	end := min([i, j + 6])
	ends := [k | some k in helpers.span(j + 1, end - 1); contains(lines[k], ";")]
	stop := _first_or(ends, end - 1)
	cont := array.slice(lines, j + 1, stop + 1)
}

_first_or(xs, d) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

_args(lines, i) := a if {
	regex.match(_proc_re, lines[i])
	parts := regex.split(_proc_re, lines[i])
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	a := _with_continuation(lines, i, rest)
}

_args(lines, i) := a if {
	not regex.match(_proc_re, lines[i])
	parts := regex.split(_method_re, lines[i])
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	a := _first_arg(_with_continuation(lines, i, rest))
}

# The first argument: literals, balanced parentheses and any other text up to
# the first top-level comma or closing parenthesis.
_first_arg(text) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\[(?:[^\[\]]|\[[^\[\]]*\])*\]|[^,()'"\[\]])*)`, text, 1)
	count(m) > 0
}

_with_continuation(lines, i, rest) := rest if contains(lines[i], ";")

_with_continuation(lines, i, rest) := concat("\n", array.concat([rest], array.slice(lines, i + 1, min([count(lines), i + 3])))) if {
	not contains(lines[i], ";")
}

_tainted_call(args, _, _) if regex.match(_source_re, args)

_tainted_call(args, l0, _) if {
	some v in l0
	_refs(args, v)
}

_tainted_call(args, _, l1) if {
	some v in l1
	_refs(args, v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_gate(content)
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, regex.replace(line, _lit_re, `''`))
	raw := _args(lines, i)
	_sql_text(line, raw)
	args := _clean(raw)
	l0 := _level0(lines, i)
	l1 := _level1(lines, i, l0)
	_tainted_call(args, l0, l1)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL injection: user input is concatenated into the query text; use a prepared statement with bound parameters (PDO/mysqli prepare + execute, pg_query_params)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ->query()/->exec()/->prepare() are generic method names (caches, HTTP
# clients, process runners). When their first argument carries a literal, the
# literal must read as SQL; a bare variable argument is accepted.
_generic_re := `(?i)->(query|exec|prepare|get_results|get_row|get_var|get_col)\s*\(`

_sql_kw_re := `(?i)\b(select|insert|update|delete|replace|create|drop|alter|truncate|where|from|into|values|union|limit|order\s+by|group\s+by|call)\b`

_sql_text(line, _) if not regex.match(_generic_re, line)

_sql_text(line, _) if regex.match(_proc_re, line)

_sql_text(line, raw) if {
	regex.match(_generic_re, line)
	not regex.match(_proc_re, line)
	lits := regex.find_n(_lit_re, raw, -1)
	count(lits) == 0
}

_sql_text(line, raw) if {
	regex.match(_generic_re, line)
	not regex.match(_proc_re, line)
	some lit in regex.find_n(_lit_re, raw, -1)
	regex.match(_sql_kw_re, lit)
}

_gate(content) if {
	some s in ["query", "Query", "exec(", "prepare(", "Raw(", "DB::", "->get_"]
	contains(content, s)
}
