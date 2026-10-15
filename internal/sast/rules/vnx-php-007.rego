package vulnetix.rules.vnx_php_007

import rego.v1

metadata := {
	"id": "VNX-PHP-007",
	"name": "PHP extract on superglobal",
	"description": "Request data is imported as local variables, letting the client overwrite any variable in scope ($is_admin, $authenticated, a file path) and bypass the checks built on them: extract() of a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, $_FILES), of a Laravel/Symfony request accessor such as $request->all(), or of a variable assigned from one in the 30 lines above (directly or via one intermediate variable); parse_str() or mb_parse_str() with no result array on a request value or $_SERVER['QUERY_STRING']; variable variables ($$key = $value or ${$key} = ...) and $GLOBALS[$key] = ... assigned inside a foreach over a superglobal; and import_request_variables(). Not reported: extract() with EXTR_PREFIX_ALL, also on a continuation line of the call (every imported name is prefixed; EXTR_SKIP still lets the client define unset variables and is reported), parse_str() with a second argument, extract() of data whose origin is not visible in the file (view data, database rows, function parameters; no cross-function dataflow), methods named extract on an object, and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-007/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [621],
	"capec": ["CAPEC-17"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["variable-overwrite", "injection", "php"],
}

_gate_re := `(?m)(\bextract\s*\(|parse_str\s*\(|\$\$\w|\$\{\s*\$|\$GLOBALS\s*\[\s*\$|import_request_variables)`

_line_re := trim_prefix(_gate_re, "(?m)")

# Checks that pin the value to a known set before the import.
_validators := `in_array|array_key_exists|preg_match`

# Every key of $_SERVER is a variable name worth overwriting, not only the
# client-controlled ones the shared source pattern lists.
_clean(s) := s

_strip_sq(s) := regex.replace(s, `(^|[^\[\s])(\s*)'(?:[^'\\]|\\.)*'`, "${1}${2}''")

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_code_line(line) if {
	t := trim_space(line)
	not startswith(t, "//")
	not startswith(t, "#")
	not startswith(t, "*")
	not startswith(t, "/*")
}

_message := "Request data is imported as local variables (variable overwrite); read the fields you need explicitly, e.g. $name = $_POST['name'] ?? ''"

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(php\d?|phtml)$`, path)
	regex.match(_gate_re, content)
	regex.match(`\$_[A-Z]|request|php://input|getallheaders|filter_input|Input::`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_line_re, line)
	_code_line(line)
	_imports(lines, i, _no_strings(line), line)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# extract(<request data>) without EXTR_PREFIX_ALL.
_imports(lines, i, code, line) if {
	regex.match(`(^|[^\w$>:\\])\\?extract\s*\(`, code)
	not regex.match(`\bfunction\s+&?extract\s*\(`, code)
	not _prefixed(lines, i)
	arg := _first_arg(line, `(^|[^\w$>:\\])\\?extract\s*\(\s*`)
	_request_data(lines, i, arg)
}

# EXTR_PREFIX_ALL on the call's line or on the continuation lines before the
# statement ends.
_prefixed(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 2]))
	contains(lines[k], "EXTR_PREFIX_ALL")
	not _ended_before(lines, i, k)
}

_ended_before(lines, i, k) if {
	some n in numbers.range(i, k - 1)
	n < k
	contains(lines[n], ";")
}

# parse_str($str) / mb_parse_str($str) with no result argument.
_imports(lines, i, code, line) if {
	regex.match(`(^|[^\w$>:\\])\\?(mb_)?parse_str\s*\(`, code)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w$>:\\])\\?(?:mb_)?parse_str\s*\(((?:[^,()]|\([^()]*\))*)\)`, line, 1)
	count(m) > 0
	_request_data(lines, i, m[0][1])
}

_imports(_, _, code, _) if regex.match(`(^|[^\w$>:\\])import_request_variables\s*\(`, code)

# $$k = ... or ${$k} = ... inside a foreach over request data.
_imports(lines, i, code, _) if {
	regex.match(`(\$\$\w+|\$\{\s*\$\w+\s*\}|\$GLOBALS\s*\[\s*\$\w+\s*\])\s*=[^=>]`, code)
	some k in numbers.range(max([0, i - 3]), i)
	m := regex.find_all_string_submatch_n(`\bforeach\s*\(\s*(.+?)\s+as\s+\$`, lines[k], 1)
	count(m) > 0
	_request_data(lines, k, m[0][1])
}

# Request data: a superglobal (any $_SERVER key), a request accessor, or a
# variable holding one.
_request_data(_, _, arg) if regex.match(`^\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b`, arg)

_request_data(lines, i, arg) if _reaches(lines, i, arg)

_first_arg(line, prefix_re) := e if {
	ms := regex.find_n(prefix_re, line, 1)
	rest := substring(line, indexof(line, ms[0]) + count(ms[0]), -1)
	m := regex.find_n(`^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,()"';]|\((?:[^()]|\([^()]*\))*\))*`, rest, 1)
	e := m[0]
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
