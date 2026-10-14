package vulnetix.rules.vnx_ruby_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-004",
	"name": "Ruby SQL injection",
	"description": "An ActiveRecord query method receives SQL text built from outside data: where/order/reorder/having/joins/find_by_sql/count_by_sql/execute/exec_query/select_all/select_value(s)/select_rows/select_one (with or without a receiver) and .select/.group/.from/.pluck/.lock/.not/.rewhere/.find_by/.exists?/.update_all/.delete_all (on a receiver) given a string whose interpolation (#{...}), concatenation (+) or format (%) inserts request input (params, request.*, cookies), a variable assigned from request input in the 15 lines above (up to two assignments), or a parameter of the enclosing method or lambda; a raw params[...] value passed as the SQL fragment (order(params[:sort])); or a variable holding such a SQL string built in the lines above. Not reported: placeholders (where(\"id = ?\", id)), hash conditions (where(id: params[:id])), values made safe with to_i/to_f/Integer(), quote/quote_table_name/sanitize_sql*, table_name/primary_key and constants, migrations under db/migrate, heredoc SQL (a documented gap), comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-004/",
	"languages": ["ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["sql-injection", "activerecord", "database"],
}

_src_re := `\bparams\b\s*(?:[\[\.\),]|$)|\brequest\.(?:params|query_parameters|request_parameters|body|raw_post|query_string|headers|cookies|referr?er|user_agent|POST|GET)\b|\bcookies\s*[\[\.]|\breq\.params\b`

_assign_re := `^\s*(@{0,2}[A-Za-z_]\w*)\s*(?:\|\||\+)?=\s*[^=~>]`

# Query methods that may be called bare inside a model (scopes, class methods).
_bare_sinks := `where|order|reorder|having|joins|select|group|pluck|find_by_sql|count_by_sql|execute|exec_query|exec_update|exec_delete|exec_insert|select_all|select_one|select_value|select_values|select_rows`

# Names that are only query methods on a receiver.
_recv_sinks := `from|lock|not|rewhere|find_by|exists\?|update_all|delete_all|calculate`

_sink_re := concat("", [
	`(?:(?:^|[^\w.:@$])(`, _bare_sinks, `)|\.(`, _bare_sinks, `|`, _recv_sinks, `))(?:\s*\(\s*|\s+)`,
])

# The methods whose name alone does not say SQL need SQL in the string.
_needs_sql_kw(name) if regex.match(`^(?:execute|exec_\w+)$`, name)

_sql_kw_re := `(?i)\b(?:select|insert|update|delete|from|where|order\s+by|group\s+by|union|values|set|join|like)\b`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
}

_ident_re(v) := concat("", [`(?:^|[^\w@:])`, v, `\b`])

_tainted(lines, i) := t1 | t2 if {
	i > 0
	lo := max([0, i - 15])
	t1 := {v |
		some j in numbers.range(lo, i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		regex.match(_src_re, l)
		not regex.match(`=\s*params\s*[\[\.].*\.(?:to_i|to_f)\b`, l)
		v := _assigned(l)
	}
	t2 := {w |
		some k in numbers.range(lo, i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		w := _assigned(l)
		some v in t1
		v != w
		regex.match(_ident_re(v), regex.replace(l, `^\s*@{0,2}\w+\s*(?:\|\||\+)?=`, ""))
	}
}

_tainted(_, 0) := set()

# Parameters of the enclosing method (nearest def above, within 40 lines) and
# of a lambda or block opened on the line itself.
_param_names(lines, i) := ps if {
	defs := [j |
		some j in numbers.range(max([0, i - 40]), i)
		regex.match(`^\s*def\s`, lines[j])
	]
	dl := _def_line(lines, defs)
	lam := [a | some m in regex.find_all_string_submatch_n(`->\s*\(([^)]*)\)|\|([^|]*)\|`, lines[i], -1); some a in [m[1], m[2]]]
	raw := concat(",", array.concat([dl], lam))
	ps := {n |
		some part in split(raw, ",")
		m := regex.find_all_string_submatch_n(`^\s*[*&]{0,2}([a-z_]\w*)`, part, 1)
		count(m) > 0
		n := m[0][1]
	}
}

_def_line(lines, defs) := "" if count(defs) == 0

_def_line(lines, defs) := a if {
	count(defs) > 0
	m := regex.find_all_string_submatch_n(`^\s*def\s+(?:self\.)?[\w?!=]+\s*\(?([^)#]*)`, lines[defs[count(defs) - 1]], 1)
	a := m[0][1]
}

_def_line(lines, defs) := "" if {
	count(defs) > 0
	not regex.match(`^\s*def\s+(?:self\.)?[\w?!=]+\s*\(?([^)#]*)`, lines[defs[count(defs) - 1]])
}

# A value made safe for SQL before it is inserted.
_safe_expr(e) if regex.match(`\.to_(?:i|f|r|d)\b|\bInteger\(|\bFloat\(|\bquote\w*\(|sanitize_sql|\b(?:quoted_)?table_name\b|\bprimary_key\b|^\s*[A-Z][A-Za-z0-9_:]*\s*$|\.(?:count|size|length)\s*$`, e)

# Expressions inserted into a string: interpolations, concatenation operands
# and format arguments.
_dyn_parts(text) := {e |
	some m in regex.find_all_string_submatch_n(`#\{([^}]*)\}`, text, -1)
	e := m[1]
} | {e |
	some m in regex.find_all_string_submatch_n(`["']\s*\+\s*([@\w][\w\.\[\]:'"?!]*)`, text, -1)
	e := m[1]
} | {e |
	some m in regex.find_all_string_submatch_n(`([@\w][\w\.\[\]:'"?!]*)\s*\+\s*["']`, text, -1)
	e := m[1]
} | {e |
	some m in regex.find_all_string_submatch_n(`["']\s*%\s*\[?([^\]\)]*)`, text, -1)
	some part in split(m[1], ",")
	e := part
}

_outside(lines, i, e, taint, ps) if {
	not _safe_expr(e)
	regex.match(_src_re, e)
}

_outside(lines, i, e, taint, ps) if {
	not _safe_expr(e)
	some v in taint | ps
	regex.match(_ident_re(v), e)
}

# A string argument with an unsafe dynamic part.
_dynamic_sql(lines, i, args, taint, ps) if {
	regex.match(`^\s*(?:Arel\.sql\(\s*)?(?:"|'|%Q|%\()`, args)
	some e in _dyn_parts(_first_arg(args))
	_outside(lines, i, e, taint, ps)
}

# The first argument: string literals and other text up to the first comma
# outside a string, so a bind value (where("name LIKE :q", q: "%#{x}%")) is
# not read as SQL.
_first_arg(args) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,"'])*)`, args, 1)
	count(m) > 0
}

# Variables assigned a dynamic SQL string in the 15 lines above.
_query_vars(lines, i, taint, ps) := {v |
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_sql_kw_re, l)
	v := _assigned(l)
	rhs := regex.replace(l, `^\s*@{0,2}\w+\s*(?:\|\||\+)?=\s*`, "")
	some e in _dyn_parts(rhs)
	_outside(lines, j, e, taint, ps)
}

_first_arg_ident(args) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(@{0,2}[a-z_]\w*)\s*(?:[,)]|$)`, args, 1)
	count(m) > 0
	v := m[0][1]
}

_reportable(lines, i, name, args) if {
	not _needs_sql_kw(name)
	taint := _tainted(lines, i)
	_dynamic_sql(lines, i, args, taint, _param_names(lines, i))
}

_reportable(lines, i, name, args) if {
	_needs_sql_kw(name)
	regex.match(_sql_kw_re, args)
	taint := _tainted(lines, i)
	_dynamic_sql(lines, i, args, taint, _param_names(lines, i))
}

# The raw request value is the SQL fragment.
_reportable(_, _, name, args) if {
	regex.match(`^(?:where|order|reorder|group|pluck|select|having|joins|from|lock|find_by_sql)$`, name)
	regex.match(`^\s*params\s*(?:\[[^\]]*\]\s*)+(?:[,)]|$)`, args)
}

_reportable(lines, i, name, args) if {
	v := _first_arg_ident(args)
	taint := _tainted(lines, i)
	v in _query_vars(lines, i, taint, _param_names(lines, i))
}

_reportable(lines, i, name, args) if {
	regex.match(`^(?:order|reorder|group|pluck|select)$`, name)
	v := _first_arg_ident(args)
	v in _tainted(lines, i)
}

_outside_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	stripped := regex.replace(prefix, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, "")
	not contains(stripped, `"`)
	not contains(stripped, "'")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	not regex.match(`(^|/)db/migrate/`, path)
	regex.match(`(?:where|order|having|joins|find_by_sql|count_by_sql|execute|exec_\w+|select\w*|group|from|pluck|lock|find_by|exists\?|update_all|delete_all|rewhere|not)\s*[\( ]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:where|order|having|joins|_sql|execute|exec_|select|group|from|pluck|lock|find_by|exists\?|_all|not)\b`, line)
	not helpers.is_comment_line(line)
	code := regex.replace(line, `\s#[^{].*$`, "")
	some m in regex.find_all_string_submatch_n(_sink_re, code, -1)
	name := _name(m)
	at := indexof(code, m[0])
	_outside_string(code, m[0])
	args := substring(code, at + count(m[0]), -1)
	_reportable(lines, i, name, args)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL built from request or caller input reaches an ActiveRecord query method; use placeholders (where(\"name = ?\", name)), hash conditions or sanitize_sql_array, and allowlist column names for order/group",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_name(m) := m[1] if m[1] != ""

_name(m) := m[2] if m[1] == ""
