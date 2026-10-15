package vulnetix.rules.vnx_php_006

import rego.v1

metadata := {
	"id": "VNX-PHP-006",
	"name": "PHP object injection via unserialize",
	"description": "unserialize() or WordPress maybe_unserialize() is called on a request value: a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, client-controlled $_SERVER keys), php://input, filter_input() or a Laravel/Symfony request accessor, inline (also wrapped in base64_decode(), urldecode() or similar) or through a variable assigned from one in the 30 lines above (directly or via one intermediate variable), without an allowed_classes option that disables or restricts object creation. A crafted payload instantiates arbitrary classes and runs their magic methods (__wakeup, __destruct), which gadget chains turn into code execution. CodeIgniter's $this->input->cookie()/post() and strtr()-decoded values count as request values. Not reported: unserialize() with ['allowed_classes' => false] or an explicit class list (inline, or as an options variable assigned that array in the 30 lines above), json_decode(), data whose origin is not visible in the file (cache, queue and session payloads the application wrote itself, function parameters; no cross-function dataflow), methods named unserialize on an object, and the call in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-006/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["deserialization", "object-injection", "php"],
}

_sink_re := `(^|[^\w$>:\\])\\?(maybe_)?unserialize\s*\(`

_gate_re := `unserialize`

# Checks that pin the value to a known shape before the call (an HMAC
# comparison authenticates it as the application's own data).
_validators := `in_array|array_key_exists|preg_match|hash_equals`

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

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(php\d?|phtml)$`, path)
	contains(content, _gate_re)
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "unserialize")
	_code_line(raw)
	line := _strip_comment(raw)
	code := _no_strings(line)
	regex.match(_sink_re, code)
	not regex.match(`\bfunction\s+&?\w+\s*\(`, code)
	locs := regex.find_n(_sink_re, code, 1)
	call := _extend(lines, i, substring(line, indexof(line, trim_left(locs[0], " \t=(.,;!")), -1))
	not _restricted(lines, i, call)
	value := _peel(substring(call, indexof(call, "(") + 1, -1))
	_reaches(lines, i, _value_head(value))
	finding := {
		"rule_id": metadata.id,
		"message": "A request value reaches unserialize() (PHP object injection); use json_decode(), or pass ['allowed_classes' => false]",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# Decoding wrappers pass the attacker's bytes through unchanged in meaning.
_wrapper_re := `^\s*\\?(base64_decode|urldecode|rawurldecode|stripslashes|stripcslashes|gzuncompress|gzinflate|gzdecode|hex2bin|str_rot13|trim|html_entity_decode|htmlspecialchars_decode|strval|strtr)\s*\(`

_peel(s) := t if {
	m1 := regex.replace(s, _wrapper_re, "")
	m2 := regex.replace(m1, _wrapper_re, "")
	t := regex.replace(m2, _wrapper_re, "")
}

# The value being deserialised: the leading superglobal, request call or
# variable, not a key used to look something up ($redis->get("s:" . $_COOKIE[...])).
_value_head(v) := h if {
	m := regex.find_n(`^\s*(\$_[A-Z]+(\s*\[[^\]]*\])*|\$request\s*->[^;]*|\$this\s*->\s*(input|request)\s*->[^;]*|\w+::\w+\s*\([^;]*|request\s*\([^;]*|file_get_contents\s*\(\s*["']php://input["']|filter_input\s*\([^)]*|getallheaders\s*\(\s*\)(\s*\[[^\]]*\])*|\$\w+(\s*\[[^\]]*\])*)`, v, 1)
	count(m) > 0
	h := m[0]
}

# allowed_classes => false, or an explicit list of classes.
_restricted(_, _, call) if regex.match(`["']allowed_classes["']\s*=>\s*(false|\[|array\s*\()`, call)

# The options passed as a variable assigned such an array a few lines above.
_restricted(lines, i, call) if {
	some m in regex.find_all_string_submatch_n(`,\s*\$(\w+)\s*\)`, call, 1)
	re := concat("", [`^\s*\$`, m[1], `\s*=[^=].*["']allowed_classes["']\s*=>\s*(false|\[|array\s*\()`])
	some k in numbers.range(max([0, i - 30]), i - 1)
	regex.match(re, lines[k])
}

# The line without a trailing // or # comment (string literals respected).
_strip_comment(s) := regex.replace(s, `^((?:[^"'/#]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|/[^/"'#])*)(//|#[^\[]).*$`, "${1}")

# Follow up to two continuation lines while the parentheses are unbalanced.
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
