package vulnetix.rules.vnx_php_004

import rego.v1

metadata := {
	"id": "VNX-PHP-004",
	"name": "PHP open redirect",
	"description": "A redirect target is taken from a request value: header('Location: ...'), wp_redirect(), redirect($url), redirect()->to()/away(), Redirect::to()/away(), new RedirectResponse(), $this->redirect() or withHeader('Location', ...) whose destination starts with (or is only prefixed by a scheme, a bare '/' or 'https://' before) a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, client-controlled $_SERVER keys such as HTTP_REFERER), filter_input() or a Laravel/Symfony request accessor, inline or through a variable assigned from one in the 30 lines above (directly or via one intermediate variable). The browser then follows the attacker's URL. Not reported: a destination whose literal prefix already fixes the host or a path ('/login?next=' . $x, 'https://example.com/' . $x, 'page.php?id=' . $x), a value checked with in_array(), array_key_exists(), preg_match() or parse_url() before the redirect, wp_safe_redirect() and redirect()->route()/back(), values whose origin is not visible in the file (no cross-function dataflow), and the calls in comments or string literals. A strpos() or str_contains() substring check is not treated as validation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-004/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1566"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["open-redirect", "web", "phishing"],
}

# header("Location: ...") is matched on the raw line (the keyword sits in a
# literal); the other redirect calls on the line with literals blanked. The
# capture ends where the destination expression starts.
_header_re := `(?i)(^|[^\w$>:\\])header\s*\(\s*(["'])\s*location\s*:\s*`

_call_re := `(^|[^\w$:\\])(wp_redirect|Redirect::(to|away)|redirect\(\s*\)\s*->\s*(to|away)|redirect|new\s+\\?(\w+\\)*RedirectResponse)\s*\(\s*|->\s*withHeader\s*\(\s*["']Location["']\s*,\s*`

_gate_re := `(?mi)(header\s*\(\s*["']\s*location|redirect|withHeader)`

_line_re := concat("", ["(?i)", trim_prefix(_gate_re, "(?mi)")])

# Checks that pin the value to a known set before the redirect.
_validators := `in_array|array_key_exists|preg_match|parse_url`

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
	endswith(path, ".php")
	regex.match(_gate_re, content)
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_line_re, line)
	_code_line(line)
	some dest in _destinations(line)
	not _pinned(dest)
	_reaches(lines, i, _expr_end(dest))
	finding := {
		"rule_id": metadata.id,
		"message": "A request value decides the redirect destination (open redirect); redirect only to relative paths or to hosts on an allowlist checked with parse_url()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The text after `Location:` (inside the header literal), or after the
# redirect call's opening parenthesis.
_destinations(line) := {d |
	regex.match(`(?i)(^|[^\w$>:])header\s*\(\s*""`, _no_strings(line))
	some m in regex.find_all_string_submatch_n(_header_re, line, 1)
	d := concat("", [m[2], substring(line, indexof(line, m[0]) + count(m[0]), -1)])
} | {d |
	code := _no_strings(line)
	regex.match(`(?i)(redirect|RedirectResponse|withHeader)(::\w+)?\s*\(`, code)
	not regex.match(`\bwp_safe_redirect\s*\(`, code)
	some m in regex.find_n(_call_re, line, 1)
	d := substring(line, indexof(line, m) + count(m), -1)
	not startswith(d, ")")
}

# The destination: the first argument, up to the first top-level comma
# (the status code and header flags are not the target).
_expr_end(d) := e if {
	m := regex.find_n(`^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,()"';]|\((?:[^()]|\([^()]*\))*\))*`, d, 1)
	e := m[0]
}

# The destination's leading literal already fixes a host or a path.
_pinned(d) if {
	lit := _leading_literal(d)
	lit != ""
	lit != "/"
	not regex.match(`^(?i)([a-z][a-z0-9+.-]*:)?//[^/?#]*$`, lit)
	not regex.match(`^(?i)[a-z][a-z0-9+.-]*:/*$`, lit)
}

# The literal text before the first interpolation or concatenation.
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
