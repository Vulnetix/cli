package vulnetix.rules.vnx_php_005

import rego.v1

metadata := {
	"id": "VNX-PHP-005",
	"name": "PHP server-side request forgery",
	"description": "A server-side fetch whose URL is decided by a request value: file_get_contents(), fopen(), file(), readfile(), get_headers(), getimagesize(), simplexml_load_file(), fsockopen(), curl_init(), curl_setopt($ch, CURLOPT_URL, ...), Laravel Http::get()/post()/... and Guzzle-style $client->get()/post()/request() on a variable named like an HTTP client, where the URL starts with (or follows only a scheme such as 'http://') a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, client-controlled $_SERVER keys), filter_input() or a Laravel/Symfony request accessor, inline or through a variable assigned from one in the 30 lines above (directly or via one intermediate variable). The server then fetches attacker-chosen URLs, including internal services and cloud metadata. Not reported: a URL whose literal prefix already fixes the host or a local directory ('https://api.example.com/users/' . $id, 'uploads/' . $name; the latter is path traversal, not SSRF), a value checked with in_array(), array_key_exists(), preg_match() or parse_url() before the call, php://input and other constant URLs, values whose origin is not visible in the file (no cross-function dataflow), ->get() on collections and other non-client receivers, and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-005/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ssrf", "web", "cloud"],
}

# Each alternative ends where the URL argument starts.
_sink_re := `(^|[^\w$>:\\])(file_get_contents|fopen|file|readfile|get_headers|getimagesize|simplexml_load_file|fsockopen|curl_init)\s*\(\s*|(^|[^\w$>:\\])curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,\s*|\bHttp::(\w+\([^()]*\)\s*->\s*)*(get|post|put|patch|delete|head|send)\s*\(\s*|\$(this\s*->\s*)?(\w*[cC]lient|http\w*|guzzle)\s*->\s*(get|post|put|patch|delete|head|getAsync|postAsync)\s*\(\s*|\$(this\s*->\s*)?(\w*[cC]lient|http\w*|guzzle)\s*->\s*(request|requestAsync)\s*\(\s*["']\w*["']\s*,\s*`

_gate_re := `(?m)(file_get_contents|fopen|\bfile\s*\(|readfile|get_headers|getimagesize|simplexml_load_file|fsockopen|curl_|Http::|[cC]lient\s*->|\$http\w*\s*->|guzzle\s*->)`

_line_re := trim_prefix(_gate_re, "(?m)")

# Checks that pin the value to a known set before the fetch.
_validators := `in_array|array_key_exists|preg_match|parse_url`

# An upload's $_FILES entry is a server-side temporary path, not a URL.
_clean(s) := regex.replace(s, `\$_FILES(\s*\[[^\]]*\])*`, "")

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
	endswith(path, ".php")
	regex.match(_gate_re, content)
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_line_re, line)
	_code_line(line)
	code := _no_strings(line)
	regex.match(_sink_re, code)
	some m in regex.find_n(_sink_re, line, -1)
	url := _first_arg(substring(line, indexof(line, m) + count(m), -1))
	url != ""
	not _pinned(url)
	_reaches(lines, i, url)
	finding := {
		"rule_id": metadata.id,
		"message": "A request value decides the URL the server fetches (SSRF); fetch only from hosts on an allowlist checked with parse_url(), and block private and link-local addresses",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The URL argument, up to the first top-level comma or the call's close.
_first_arg(d) := e if {
	m := regex.find_n(`^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,()"';]|\((?:[^()]|\([^()]*\))*\))*`, d, 1)
	e := trim_space(m[0])
}

# The URL's leading literal already fixes a host or a local path: only a
# bare scheme, '//' or an unterminated host leaves the destination open.
_pinned(d) if {
	lit := _leading_literal(d)
	lit != ""
	not regex.match(`^(?i)([a-z][a-z0-9+.-]*:)?//[^/?#]*$`, lit)
	not regex.match(`^(?i)[a-z][a-z0-9+.-]*:/*$`, lit)
}

# A complete literal with no interpolation is a constant URL.
_pinned(d) if regex.match(`^\s*("[^"$]*"|'[^']*')\s*$`, d)

# A constant expression (a literal with no interpolation, or a constant
# prefix such as __DIR__ or a CONSTANT) fixes the destination too.
_pinned(d) if regex.match(`^\s*(__DIR__|dirname\s*\(|[A-Z][A-Z0-9_]+\b|storage_path\s*\(|base_path\s*\(|public_path\s*\()`, d)

_leading_literal(d) := lit if {
	m := regex.find_all_string_submatch_n(`^\s*["']([^"'$\{\\]*)`, d, 1)
	count(m) > 0
	lit := m[0][1]
}

# ── Local one-file taint tracking for PHP ────────────────────────────────
# A request value: a superglobal, the raw body, a request header, or the
# Laravel/Symfony request accessors. $_SERVER keys the client controls only.
_source_re := `\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"](HTTP_\w+|QUERY_STRING|REQUEST_URI|PATH_INFO|PHP_SELF)|php://input|\$request\s*->\s*(input|get|query|post|all|cookie|header|route|string|json)\s*\(|\$request\s*->\s*(query|request|cookies|headers)\s*->\s*get\s*\(|\bRequest::(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*\)\s*->\s*(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*['"]|\bInput::(get|all)\s*\(|\bfilter_input\s*\(\s*INPUT_(GET|POST|COOKIE|REQUEST|SERVER)|\bgetallheaders\s*\(`

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
