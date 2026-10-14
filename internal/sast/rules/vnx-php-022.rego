package vulnetix.rules.vnx_php_022

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-022",
	"name": "PHP open redirect via non-literal redirect destination",
	"description": "A redirect destination comes from the request: header('Location: ...') (any case, with or without a space before the parenthesis, concatenated or interpolated), Laravel redirect($x), redirect()->to()/away(), Redirect::to()/away(), Symfony $this->redirect() and new RedirectResponse() (also split across lines), wp_redirect() or withHeader('Location', ...), where the destination starts with a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, client-controlled $_SERVER keys such as HTTP_REFERER), filter_input() or a Laravel/Symfony request accessor, inline or through a variable assigned from one in the 25 lines above (directly or via one intermediate variable). The browser then follows an attacker-chosen URL, which makes phishing links look like they belong to the site. Not reported: literal destinations, a destination whose literal prefix already fixes the host or a path ('/login?next=' . $x, 'https://example.com/cb?state=' . $x), a value checked with in_array(), array_key_exists(), preg_match() or parse_url() or replaced by a constant (switch/allowlist) before the redirect, redirect()->route()/back(), configuration values, values whose origin is not visible in the file, and calls in comments or string literals. A strpos() substring check is not treated as validation. This overlaps VNX-PHP-004, which covers the same weakness.",
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

_header_re := `(?i)(?:^|[^\w$>:\\])header\s*\(\s*(["'])\s*location\s*:\s*`

_header_code_re := `(?i)(^|[^\w$>:\\])header\s*\(`

_call_re := `(?:^|[^\w$:\\])(?:wp_redirect|Redirect::(?:to|away)|redirect\(\s*\)\s*->\s*(?:to|away)|redirect|new\s+\\?(?:\w+\\)*RedirectResponse)\s*\(\s*|->\s*withHeader\s*\(\s*["']Location["']\s*,\s*`

_gate_re := `(?i)(header\s*\(\s*["']\s*location|redirect|withHeader)`

_validators := `in_array|array_key_exists|preg_match|parse_url`

# ── Local one-file taint tracking for PHP ────────────────────────────────
_source_re := `\$_(GET|POST|REQUEST|COOKIE)\b|\$_SERVER\s*\[\s*['"](HTTP_\w+|QUERY_STRING|REQUEST_URI|PATH_INFO|PHP_SELF)|\$request\s*->\s*(input|get|query|post|all|cookie|header|route|string)\s*\(|\$request\s*->\s*(query|request|cookies|headers)\s*->\s*get\s*\(|\bRequest::(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*\)\s*->\s*(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*['"]|\bInput::(get|all)\s*\(|\bfilter_input\s*\(\s*INPUT_(GET|POST|COOKIE|REQUEST|SERVER)`

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
		some k in numbers.range(max([0, i - 25]), i - 1)
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

# After `Location:` inside the header literal, reopened with its own quote.
_destinations(line, stmt) := _hdr_dests(line) | _call_dests(line, stmt)

_hdr_dests(line) := {d |
	regex.match(_header_code_re, _no_strings(line))
	some m in regex.find_all_string_submatch_n(_header_re, line, 1)
	d := concat("", [m[1], substring(line, indexof(line, m[0]) + count(m[0]), -1)])
}

_call_dests(line, stmt) := {d |
	code := _no_strings(line)
	regex.match(`(?i)(redirect|RedirectResponse|withHeader)\s*(\(|::)`, code)
	not regex.match(`\bwp_safe_redirect\s*\(`, code)
	some m in regex.find_n(_call_re, stmt, 1)
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
	endswith(path, ".php")
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)location|redirect`, line)
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
