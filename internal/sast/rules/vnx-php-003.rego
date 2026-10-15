package vulnetix.rules.vnx_php_003

import rego.v1

metadata := {
	"id": "VNX-PHP-003",
	"name": "PHP file inclusion with variable path",
	"description": "An include, require, include_once or require_once statement whose path contains a request value: a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, client-controlled $_SERVER keys), php://input, filter_input() or a Laravel/Symfony request accessor, inline or through a variable assigned from one in the 30 lines above (directly or via one intermediate variable, so str_replace() blacklists of ../ or http:// still count). That is Local File Inclusion, and Remote File Inclusion where allow_url_include is on, both leading to code execution. The statement may span lines. Not reported: a path passed through basename(), intval() or a preg_replace() that deletes every character outside a letters/digits/_/- class, a file looked up in a map by the request value ($pages[$_GET['p']]; the map variable is still followed), a value checked with in_array(), array_key_exists(), isset($map[$v]) or preg_match() before the include, constant paths and __DIR__-relative paths built from constants, variables whose origin is not visible in the file (a value set in another included file or passed as a function parameter is a documented gap), and the keywords in comments (including trailing // and # comments) or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-003/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [98],
	"capec": ["CAPEC-193"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["file-inclusion", "lfi", "rfi", "rce"],
}

# The language construct, with or without parentheses: not ->include( or a
# method named require.
_sink_re := `(^|[^\w$>:\\])(include|require)(_once)?\b\s*\(?`

_gate_re := `\b(include|require)(_once)?\b[^;]{0,300}\$`

_line_re := `\b(include|require)(_once)?\b`

_sanitiser_re := `\b(basename|intval|absint)\s*\((?:[^()]|\([^()]*\))*\)|\((int|integer)\)\s*\$\w+(\s*\[[^\]]*\])*|\bpreg_replace\s*\(\s*(['"])/\[\^[A-Za-z0-9_\\-]*\][+*]?/[a-zA-Z]*['"]\s*,\s*(''|"")\s*,(?:[^()]|\([^()]*\))*\)`

# A lookup in a map ($pages[$_GET['p']]) yields the map's value, not the
# request value: the index is dropped and only the map variable is followed,
# so a map that is itself request data ($params = $request->getQueryParams())
# still counts.
_unindex(s) := regex.replace(s, `(\$[A-Za-z]\w*)\s*\[(?:[^\[\]]|\[[^\[\]]*\])*\]`, "${1}[]")

# Checks that pin the value to a known set before the include.
_validators := `in_array|array_key_exists|preg_match|ctype_\w+|is_numeric`

_clean(s) := _unindex(regex.replace(s, _sanitiser_re, ""))

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
	_reaches(lines, i, expr)
	finding := {
		"rule_id": metadata.id,
		"message": "A request value reaches include/require (local or remote file inclusion); map the request value to a fixed file through an allowlist instead of building the path from it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# The line without a trailing // or # comment (string literals respected).
_strip_comment(s) := regex.replace(s, `^((?:[^"'/#]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|/[^/"'#])*)(//|#[^\[]).*$`, "${1}")

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# The statement's path expression: from the keyword to the end of the
# statement.
_sink_exprs(lines, i, line) := {e |
	code := _no_strings(line)
	regex.match(_sink_re, code)
	locs := regex.find_all_string_submatch_n(_sink_re, code, 1)
	rest := substring(line, indexof(line, locs[0][0]), -1)
	e := _statement(lines, i, rest)
}

_statement(_, _, s) := s if contains(s, ";")

_statement(lines, i, s) := concat("\n", array.concat([s], [lines[k] | some k in numbers.range(i + 1, min([count(lines) - 1, i + 2]))])) if not contains(s, ";")

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
}

_tainted(lines, i, v) if {
	j := _origin(lines, i, v)
	rhs := _clean(_rhs(lines[j]))
	not regex.match(_source_re, rhs)
	some w in _vars(rhs)
	k := _origin(lines, j, w)
	regex.match(_source_re, _clean(_rhs(lines[k])))
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
