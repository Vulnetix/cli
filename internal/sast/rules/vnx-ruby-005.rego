package vulnetix.rules.vnx_ruby_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-005",
	"name": "Ruby XSS via html_safe or raw",
	"description": "Rails output escaping is switched off for a value that is not a fixed string: .html_safe called on a model attribute, a variable, a method result or an interpolated string; raw(...) / raw x, <%== x %> in ERB, != x in Haml and == x in Slim given the same. An interpolated string literal is reported when one of its #{...} parts is not known safe. Not reported: string literals without interpolation (or whose interpolations are only ids, to_i values, counts, path/url helpers, h()/sanitize() results or constants), a local assigned only from such a literal, values from sanitize/strip_tags/h/html_escape/escape_javascript/json_escape, translations (t/I18n.t), Rails tag and link helpers, render/partial/yield/content_for/capture output, safe_join, CONSTANTS, the html_safe? predicate, the word raw inside a Ruby string literal, comments. Whether a reported value can actually hold user-controlled markup is not proven: a stored attribute rendered with html_safe is reported because that is how stored XSS is written.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-005/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "rails", "html-safe"],
}

_view_or_ruby(path) if regex.match(`\.(?:rb|erb|haml|slim)$`, path)

# The receiver of .html_safe: a string literal (with any method chain), or an
# identifier chain with calls and indexing.
_recv_re := `("(?:[^"\\]|\\.)*"(?:\.\w+[?!]?(?:\([^()]*\))?)*|'(?:[^'\\]|\\.)*'(?:\.\w+[?!]?(?:\([^()]*\))?)*|[@$]?[A-Za-z_][\w:]*[?!]?(?:\([^()]*\)|\[[^\]]*\])*(?:\.[A-Za-z_]\w*[?!]?(?:\([^()]*\)|\[[^\]]*\])*)*)\.html_safe(?:[^?\w]|$)`

_raw_paren_re := `(?:^|[^\w.:])raw\s*\(\s*((?:[^()]|\([^()]*\))*)\)`

_raw_bare_re := `(?:<%=|^\s*=|^\s*[%.#][\w.#-]*=)\s*raw\s+([^\s(%=,)][^%]*?)\s*(?:-?%>|$)`

_erb_raw_re := `<%==\s*(.+?)\s*-?%>`

_haml_raw_re := `^\s*(?:[%.#][\w.#-]*(?:\{[^}]*\})?)?\s*!=\s*(.+)$`

# Expressions whose result is escaped, fixed or markup Rails built itself.
_safe_call_re := `^(?:(?:ERB::Util\.|CGI\.|Rack::Utils\.|ActionController::Base\.helpers\.|helpers\.)?(?:sanitize|strip_tags|html_escape|escape_html|escape_once|escapeHTML|h|j|escape_javascript|json_escape|t|translate|l|localize|safe_join|content_tag|tag|link_to|button_to|mail_to|image_tag|javascript_tag|render|partial|yield|yield_content|content_for|capture|haml|erb|simple_format|number_\w+|pluralize|time_ago_in_words)\b|I18n\.t\b|[A-Z][A-Z0-9_]*(?:::[A-Z][A-Z0-9_]*)*\s*$|[a-z_]\w*_(?:path|url)\b)`

_safe_interp_re := `(?:\.id|\.to_i|\.to_f|\.count|\.size|\.length)\s*$|^\s*\w+_(?:path|url)\b|^\s*(?:h|sanitize|html_escape|strip_tags|t|j|escape_javascript)\s*[\( ]|^\s*[A-Z][A-Z0-9_]*\s*$|^\s*\d+\s*$`

_literal(e) if regex.match(`^\s*["']`, e)

_unsafe(e, _, _) if {
	_literal(e)
	startswith(trim_space(e), `"`)
	some m in regex.find_all_string_submatch_n(`#\{([^}]*)\}`, e, -1)
	not regex.match(_safe_interp_re, m[1])
}

_unsafe(e, lines, i) if {
	not _literal(e)
	x := trim_space(e)
	x != ""
	not regex.match(_safe_call_re, x)
	not _literal_local(lines, i, x)
	not regex.match(`^\d`, x)
}

# A local assigned only from fixed literals in the 10 lines above.
_literal_local(lines, i, x) if {
	regex.match(`^[a-z_]\w*$`, x)
	lo := max([0, i - 10])
	i > 0
	assigns := [l |
		some j in numbers.range(lo, i - 1)
		l := lines[j]
		regex.match(concat("", [`^\s*`, x, `\s*(?:\|\|=|\+=|<<|=)[^=]`]), l)
	]
	count(assigns) > 0
	every l in assigns {
		rhs := regex.replace(l, concat("", [`^\s*`, x, `\s*(?:\|\|=|\+=|<<|=)\s*`]), "")
		regex.match(`^(?:'[^']*'|"[^"#]*")\s*(?:\.freeze)?\s*$`, rhs)
	}
}

_exprs(path, code) := {e |
	some m in regex.find_all_string_submatch_n(_recv_re, code, -1)
	e := m[1]
} | {e |
	some m in regex.find_all_string_submatch_n(_raw_paren_re, code, -1)
	_raw_ok(path, code, m[0])
	e := m[1]
} | {e |
	some m in regex.find_all_string_submatch_n(_raw_bare_re, code, -1)
	_raw_ok(path, code, m[0])
	e := m[1]
} | {e |
	some m in regex.find_all_string_submatch_n(_erb_raw_re, code, -1)
	e := m[1]
} | {e |
	endswith(path, ".haml")
	some m in regex.find_all_string_submatch_n(_haml_raw_re, code, -1)
	e := m[1]
} | {e |
	endswith(path, ".slim")
	some m in regex.find_all_string_submatch_n(_slim_raw_re, code, -1)
	e := m[1]
}

# In Ruby source, `raw (` inside a string literal (a log message) is text.
_raw_ok(path, _, _) if not endswith(path, ".rb")

_raw_ok(path, code, tok) if {
	endswith(path, ".rb")
	prefix := substring(code, 0, indexof(code, tok) + indexof(tok, "raw"))
	stripped := regex.replace(prefix, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, "")
	not contains(stripped, `"`)
	not contains(stripped, "'")
}

# Slim's unescaped output: `== expr`, alone or after a tag (`p.body == x`).
_slim_raw_re := `^\s*(?:[a-z][\w-]*)?(?:[.#][\w-]+)*\s*==\s*(.+)$`

# A Ruby line's text outside a trailing comment; ERB lines are kept whole.
_code(path, line) := regex.replace(line, `\s#[^{].*$`, "") if endswith(path, ".rb")

_code(path, line) := line if not endswith(path, ".rb")

findings contains finding if {
	some path, content in input.file_contents
	_view_or_ruby(path)
	_gate(path, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.html_safe|\braw[\s(]|<%==|^\s*(?:[%.#][\w.#-]*(?:\{[^}]*\})?)?\s*!=|^\s*[\w.#-]*\s*==`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*<%#`, line)
	code := _code(path, line)
	some e in _exprs(path, code)
	_unsafe(e, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "html_safe/raw/<%== %> marks a non-constant value as safe HTML and skips Rails escaping; escape it (h, sanitize with an allowlist) or build the markup with content_tag/safe_join",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_gate(path, content) if {
	endswith(path, ".slim")
	regex.match(`(?m)\.html_safe|\braw[\s(]|^\s*(?:[a-z][\w-]*)?(?:[.#][\w-]+)*\s*==`, content)
}

_gate(path, content) if {
	not endswith(path, ".haml")
	not endswith(path, ".slim")
	regex.match(`\.html_safe|\braw[\s(]|<%==`, content)
}

_gate(path, content) if {
	endswith(path, ".haml")
	regex.match(`(?m)\.html_safe|\braw[\s(]|^\s*(?:[%.#][\w.#-]*(?:\{[^}]*\})?)?\s*!=`, content)
}
