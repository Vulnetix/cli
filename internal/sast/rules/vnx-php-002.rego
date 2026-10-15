package vulnetix.rules.vnx_php_002

import rego.v1

metadata := {
	"id": "VNX-PHP-002",
	"name": "Dangerous function in PHP",
	"description": "A PHP command or code execution sink (exec(), system(), passthru(), shell_exec(), popen(), proc_open(), pcntl_exec(), the backtick operator, or eval()) receives a request value: a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES, client-controlled $_SERVER keys), php://input, getallheaders(), filter_input() or a Laravel/Symfony request accessor, either inline or through a variable assigned from one in the 30 lines above (directly or via one intermediate variable). Not reported: an argument passed through escapeshellarg(), escapeshellcmd(), intval(), an (int)/(float) cast or a numeric filter_var() filter, a variable checked with in_array(), preg_match(), ctype_*(), is_numeric() or filter_var() before the call, constant commands, a command chosen by a match expression whose arms are all literals, function parameters and other values whose origin is not visible in the file (no cross-function dataflow), methods named exec/system on an object or class, declarations, and the names in comments (including a trailing // or # comment) or string literals. .php and .phtml files are scanned.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-002/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "code-injection", "dangerous-function"],
}

# A call of the global function, not $obj->exec(), Foo::system() or $exec(.
_sink_re := `(^|[^\w$>:\\])\\?(eval|exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(`

# The backtick shell operator around an interpolated PHP variable.
_backtick_re := "(=|\\becho|\\bprint|\\breturn|\\()\\s*`[^`]*\\$[A-Za-z_][^`]*`"

_gate_re := "(?m)(\\b(eval|exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\\s*\\(|`[^`\\n]*\\$[A-Za-z_])"

_line_re := trim_prefix(_gate_re, "(?m)")

_sanitiser_re := `\b(escapeshellarg|escapeshellcmd|intval|floatval|absint)\s*\((?:[^()]|\([^()]*\))*\)|\((int|integer|float)\)\s*\$\w+(\s*\[[^\]]*\])*|\bfilter_var\s*\((?:[^()]|\([^()]*\))*FILTER_(VALIDATE_(INT|FLOAT|IP)|SANITIZE_NUMBER_\w+)[^)]*\)`

# Checks that pin the value to a known set before the call.
_validators := `in_array|array_key_exists|preg_match|ctype_\w+|is_numeric|filter_var`

# The upload's tmp_name, size and error are set by PHP, not the client.
_clean(s) := regex.replace(regex.replace(s, _sanitiser_re, ""), `\$_FILES\s*\[[^\]]*\]\s*\[\s*["'](tmp_name|size|error)["']\s*\]`, "")

_strip_sq(s) := regex.replace(s, `(^|[^\[\s])(\s*)'(?:[^'\\]|\\.)*'`, "${1}${2}''")

_code_line(line) if {
	t := trim_space(line)
	not startswith(t, "//")
	not startswith(t, "#")
	not startswith(t, "*")
	not startswith(t, "/*")
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(php\d?|phtml)$`, path)
	regex.match(_gate_re, content)
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(_line_re, raw)
	_code_line(raw)
	line := _strip_comment(raw)
	some expr in _sink_exprs(lines, i, line)
	not regex.match(`\bfunction\s+&?\w+\s*\(`, line)
	_reaches(lines, i, expr)
	finding := {
		"rule_id": metadata.id,
		"message": "A request value reaches a command or code execution function; pass each argument through escapeshellarg(), validate it against an allowlist, or avoid the shell (and never eval() request data)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# The line without a trailing // or # comment (string literals respected).
_strip_comment(s) := regex.replace(s, `^((?:[^"'/#]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|/[^/"'#])*)(//|#[^\[]).*$`, "${1}")

# Both kinds of string literal blanked: where a sink call may sit.
_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_sink_exprs(lines, i, line) := {e |
	code := _no_strings(line)
	regex.match(_sink_re, code)
	locs := regex.find_all_string_submatch_n(_sink_re, code, 1)
	e := _call_text(lines, i, substring(line, indexof(line, locs[0][0]), -1))
} | {e |
	some e in regex.find_n(_backtick_re, line, 1)
}

# The sink's own text: from the match to the end of the call, following up to
# two continuation lines while the parentheses are unbalanced.
_call_text(lines, i, first) := _extend(lines, i, first)

_extend(_, _, s) := s if count(regex.find_n(`\(`, s, -1)) <= count(regex.find_n(`\)`, s, -1))

_extend(lines, i, s) := t if {
	count(regex.find_n(`\(`, s, -1)) > count(regex.find_n(`\)`, s, -1))
	more := [lines[k] | some k in numbers.range(i + 1, min([count(lines) - 1, i + 2]))]
	t := concat("\n", array.concat([s], more))
}

# ── Local one-file taint tracking for PHP ────────────────────────────────
# A request value: a superglobal, the raw body, a request header, or the
# Laravel/Symfony request accessors. $_SERVER keys the client controls only.
_source_re := `\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"](HTTP_\w+|QUERY_STRING|REQUEST_URI|PATH_INFO|PHP_SELF)|php://input|\$request\s*->\s*(input|get|query|post|all|cookie|header|route|string|json|getContent)\s*\(|\$request\s*->\s*(query|request|cookies|headers)\s*->\s*get\s*\(|\bRequest::(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*\)\s*->\s*(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*['"]|\bInput::(get|all)\s*\(|\bfilter_input\s*\(\s*INPUT_(GET|POST|COOKIE|REQUEST|SERVER)|\bgetallheaders\s*\(|\$this\s*->\s*input\s*->\s*(get|post|get_post|post_get|cookie|server|request_headers|get_request_header|raw_input_stream)\b|\$this\s*->\s*request\s*->\s*(getVar|getGet|getPost|getGetPost|getPostGet|getCookie|getJSON|getJsonVar|getRawInput|getBody|getHeaderLine)\s*\(|->\s*(getQueryParams|getParsedBody|getCookieParams)\s*\(\s*\)`

# Variables an expression reads, ignoring $this and superglobals.
_vars(s) := {v |
	some m in regex.find_all_string_submatch_n(`\$([A-Za-z_]\w*)`, _strip_sq(s), -1)
	v := m[1]
	not startswith(v, "_")
	v != "this"
}

_rhs(line) := regex.replace(line, `^\s*\$\w+\s*\.?=`, "")

_reads(s, v) if regex.match(concat("", [`\$`, v, `\b`]), _strip_sq(s))

# Where $v at line i got its value: the nearest assignment in the 30 lines
# above whose (sanitiser-free) right-hand side does not read $v itself.
# In-place rewrites ($f = str_replace("../", "", $f)) keep the origin; an
# in-place sanitiser ($f = basename($f)) becomes the origin and clears it.
_origin(lines, i, v) := j if {
	re := concat("", [`^\s*\$`, v, `\s*\.?=[^=>]`])
	cands := [k |
		some k in numbers.range(max([0, i - 30]), i - 1)
		k < i
		regex.match(re, lines[k])
		not _reads(_clean(_rhs(lines[k])), v)
	]
	count(cands) > 0
	j := max(cands)
}

# $v at line i holds a request value: its origin reads one, or reads a
# variable whose own origin does (one hop), with no sanitiser on the way.
_tainted(lines, i, v) if {
	j := _origin(lines, i, v)
	regex.match(_source_re, _clean(_rhs(lines[j])))
	not _literal_match(lines, j)
}

_tainted(lines, i, v) if {
	j := _origin(lines, i, v)
	rhs := _clean(_rhs(lines[j]))
	not regex.match(_source_re, rhs)
	not _literal_match(lines, j)
	some w in _vars(rhs)
	k := _origin(lines, j, w)
	regex.match(_source_re, _clean(_rhs(lines[k])))
}

# $v = match ($x) { 'a' => 'literal', ... }: the request value only selects
# one of the constant arms, so $v does not carry it.
_literal_match(lines, j) if {
	regex.match(`=\s*match\s*\([^)]*\)\s*\{?\s*$`, lines[j])
	arms := [k |
		some k in numbers.range(j + 1, min([count(lines) - 1, j + 15]))
		not regex.match(`^\s*\}`, lines[k])
		not _closed_before(lines, j, k)
	]
	count(arms) > 0
	every k in arms {
		regex.match(`^\s*(\{\s*)?[^$]*=>\s*("[^"$]*"|'[^']*'|-?\d+|null|true|false)\s*,?\s*$`, lines[k])
	}
}

_closed_before(lines, j, k) if {
	some m in numbers.range(j + 1, k - 1)
	m < k
	regex.match(`^\s*\}`, lines[m])
}

# The value was checked against an allowlist or a strict pattern between
# its origin and the sink.
_validated(lines, i, v) if {
	j := _origin(lines, i, v)
	re := concat("", [`\b(`, _validators, `)\s*\([^;]*\$`, v, `\b|\bisset\s*\(\s*\$\w+\s*\[\s*\$`, v, `\s*\]`])
	some k in numbers.range(j, i - 1)
	regex.match(re, lines[k])
}

# The expression reaches the sink unsanitised: a request value inline, or a
# tainted variable that was not validated on the way.
_reaches(_, _, expr) if regex.match(_source_re, _clean(expr))

_reaches(lines, i, expr) if {
	some v in _vars(_clean(expr))
	_tainted(lines, i, v)
	not _validated(lines, i, v)
}
