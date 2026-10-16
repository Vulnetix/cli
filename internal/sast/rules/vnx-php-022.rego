package vulnetix.rules.vnx_php_022

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-022",
	"name": "PHP open redirect via non-literal redirect destination",
	"description": "A framework redirect helper's destination comes from the request: Laravel and CodeIgniter redirect($x), redirect()->to()/away(), Redirect::to()/away(), Symfony $this->redirect() and new RedirectResponse() (also split across lines), where the destination starts with a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES, client-controlled $_SERVER keys such as HTTP_REFERER), filter_input(), getallheaders(), a Laravel/Symfony/CodeIgniter/PSR-7 request accessor or php://input, inline or through a variable assigned from one in the 30 lines above (directly or via one intermediate variable). The browser then follows an attacker-chosen URL, which makes phishing links look like they belong to the site. Not reported: literal destinations, a destination whose literal prefix already fixes the host or a path ('/login?next=' . $x, 'https://example.com/cb?state=' . $x), a value checked with in_array(), array_key_exists(), preg_match() or parse_url() or replaced by a constant (switch/allowlist) before the redirect, redirect()->route()/back()/intended(), configuration values, values whose origin is not visible in the file, and calls in comments or string literals. A strpos() substring check is not treated as validation. A raw header('Location: ...') or Refresh header, wp_redirect() and PSR-7 withHeader('Location', ...) are reported by VNX-PHP-004.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-022/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1598"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["open-redirect", "redirect", "symfony", "laravel", "php"],
}

# The framework redirect helpers: Laravel/CodeIgniter redirect($x),
# redirect()->to()/away(), Redirect::to()/away(), Symfony new
# RedirectResponse() and $this->redirect(). A raw header('Location: ...'),
# wp_redirect() and PSR-7 withHeader('Location', ...) are reported by
# VNX-PHP-004, so one redirect is one finding.
_call_re := `(?:^|[^\w$:\\])(?:Redirect::(?:to|away)|redirect\(\s*\)\s*->\s*(?:to|away)|redirect|new\s+\\?(?:\w+\\)*RedirectResponse)\s*\(\s*`

_gate_re := `(?i)redirect`

_validators := `in_array|array_key_exists|preg_match|parse_url`

# ── Local one-file taint tracking for PHP ────────────────────────────────
_source_re := `\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"](HTTP_\w+|QUERY_STRING|REQUEST_URI|PATH_INFO|PHP_SELF)|php://input|\$request\s*->\s*(input|get|query|post|all|cookie|header|route|string|json|getContent)\s*\(|\$request\s*->\s*(query|request|cookies|headers)\s*->\s*get\s*\(|\bRequest::(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*\)\s*->\s*(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*['"]|\bInput::(get|all)\s*\(|\bfilter_input\s*\(\s*INPUT_(GET|POST|COOKIE|REQUEST|SERVER)|\bgetallheaders\s*\(|\$this\s*->\s*input\s*->\s*(get|post|get_post|post_get|cookie|server|request_headers|get_request_header|raw_input_stream)\b|\$this\s*->\s*request\s*->\s*(getVar|getGet|getPost|getGetPost|getPostGet|getCookie|getJSON|getJsonVar|getRawInput|getBody|getHeaderLine)\s*\(|->\s*(getQueryParams|getParsedBody|getCookieParams)\s*\(\s*\)`

_strip_sq(s) := regex.replace(s, `(^|[^\[\s])(\s*)'(?:[^'\\]|\\.)*'`, "${1}${2}''")

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_vars(s) := {v |
	some m in regex.find_all_string_submatch_n(`\$([A-Za-z_]\w*)`, _strip_sq(s), -1)
	v := m[1]
	not startswith(v, "_")
	v != "this"
}

_rhs(line) := regex.replace(line, `^\s*\$\w+\s*\.?=`, "")

_reads(s, v) if regex.match(concat("", [`\$`, v, `\b`]), _strip_sq(s))

_origin(lines, i, v) := j if {
	re := concat("", [`^\s*\$`, v, `\s*\.?=[^=>]`])
	cands := [k |
		some k in numbers.range(max([0, i - 30]), i - 1)
		k < i
		regex.match(re, lines[k])
		not _reads(_rhs(lines[k]), v)
	]
	count(cands) > 0
	j := max(cands)
}

_tainted(lines, i, v) if {
	j := _origin(lines, i, v)
	regex.match(_source_re, _rhs(lines[j]))
	not _validated(lines, j, i, v)
}

_tainted(lines, i, v) if {
	j := _origin(lines, i, v)
	rhs := _rhs(lines[j])
	not regex.match(_source_re, rhs)
	some w in _vars(rhs)
	k := _origin(lines, j, w)
	regex.match(_source_re, _rhs(lines[k]))
	not _validated(lines, k, i, w)
}

_validated(lines, j, i, v) if {
	re := concat("", [`\b(`, _validators, `)\s*\([^;]*\$`, v, `\b|\bisset\s*\(\s*\$\w+\s*\[\s*\$`, v, `\s*\]`])
	some k in numbers.range(j, i - 1)
	regex.match(re, lines[k])
}

# ── Destinations ─────────────────────────────────────────────────────────
_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 4])
	s := concat(" ", array.slice(lines, i, end + 1))
}

# The text after the redirect helper's opening parenthesis; the call must
# start on this line.
_destinations(line, stmt) := {d |
	code := _no_strings(line)
	regex.match(`(?i)(redirect|RedirectResponse)\s*(\(|::)`, code)
	some m in regex.find_n(_call_re, stmt, 1)
	indexof(stmt, m) < count(line)
	d := substring(stmt, indexof(stmt, m) + count(m), -1)
	not startswith(d, ")")
}

# The destination argument only: the first call argument (balanced
# literals and one level of nested parentheses), so a chained ->withInput()
# or a status argument is not read as the destination.
_arg := `(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\((?:[^()'"]|'[^']*'|"[^"]*"|\([^()]*\))*\)|\[[^\[\]]*\]|[^,'"()\[\];])+`

_expr_end(d) := e if {
	m := regex.find_n(concat("", [`^\s*`, _arg]), d, 1)
	count(m) > 0
	e := m[0]
}

_pinned(d) if {
	lit := _leading_literal(d)
	lit != ""
	lit != "/"
	not regex.match(`^(?i)([a-z][a-z0-9+.-]*:)?//[^/?#]*$`, lit)
	not regex.match(`^(?i)[a-z][a-z0-9+.-]*:/*$`, lit)
}

# A destination that is only a literal is not a request value.
_pinned(d) if regex.match(`^\s*(?:'[^'$]*'|"[^"$]*")\s*(?:[,)]|$)`, d)

_leading_literal(d) := lit if {
	m := regex.find_all_string_submatch_n(`^\s*["']([^"'$\{\\]*)`, d, 1)
	count(m) > 0
	lit := m[0][1]
}

_reaches(_, _, expr) if regex.match(_source_re, expr)

_reaches(lines, i, expr) if {
	some v in _vars(expr)
	_tainted(lines, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(php\d?|phtml)$`, path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)redirect`, line)
	not helpers.is_comment_line(line)
	some dest in _destinations(line, _stmt(lines, i))
	not _pinned(dest)
	_reaches(lines, i, _expr_end(dest))
	finding := {
		"rule_id": metadata.id,
		"message": "The redirect destination is taken from the request (open redirect); redirect to a relative path or a route name, or check the host with parse_url() against an allowlist first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
