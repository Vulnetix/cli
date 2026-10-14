package vulnetix.rules.vnx_php_017

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-017",
	"name": "PHP LDAP injection via user-controlled filter",
	"description": "ldap_search(), ldap_list() or ldap_read() receives a request value in its filter or base DN: a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, client-controlled $_SERVER keys), filter_input() or a Laravel/Symfony request accessor, inline in the call or through a variable assigned from one in the 25 lines above (directly or via one intermediate variable, including sprintf() and .= concatenation). An attacker can then rewrite the filter ('*)(uid=*))(|(uid=*') to bypass a login or enumerate the directory. Not reported: values passed through ldap_escape(), intval()/(int), ctype_*(), filter_var() or is_numeric(), values checked with preg_match(), ctype_*(), in_array() or filter_var() before the call, constant or configuration filters, values whose origin is not visible in the file (no cross-function dataflow), and calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-017/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [90],
	"capec": ["CAPEC-136"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ldap-injection", "injection", "php"],
}

_sink_re := `(^|[^\w$>:\\])ldap_(search|list|read)\s*\(`

# ── Local one-file taint tracking for PHP ────────────────────────────────
_source_re := `\$_(GET|POST|REQUEST|COOKIE)\b|\$_SERVER\s*\[\s*['"](HTTP_\w+|QUERY_STRING|REQUEST_URI|PATH_INFO|PHP_SELF)|php://input|\$request\s*->\s*(input|get|query|post|all|cookie|header|route|string|json)\s*\(|\$request\s*->\s*(query|request|cookies|headers)\s*->\s*get\s*\(|\bRequest::(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*\)\s*->\s*(input|get|query|post|all|cookie|header)\s*\(|\brequest\(\s*['"]|\bInput::(get|all)\s*\(|\bfilter_input\s*\(\s*INPUT_(GET|POST|COOKIE|REQUEST|SERVER)`

_sanitiser_re := `\b(ldap_escape|intval|floatval|ctype_\w+|filter_var|is_numeric)\s*\(|\(\s*(int|integer|float|bool)\s*\)`

_validator_re(v) := concat("", [`\b(preg_match|ctype_\w+|in_array|filter_var|is_numeric|array_key_exists)\s*\([^;]*\$`, v, `\b`])

# Single-quoted literals do not interpolate; array keys ($_GET['x']) are kept.
_strip_sq(s) := regex.replace(s, `(^|[^\[\s])(\s*)'(?:[^'\\]|\\.)*'`, "${1}${2}''")

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# ldap_escape(...) calls inside the statement neutralise what they wrap.
_unescaped(s) := regex.replace(s, `\bldap_escape\s*\((?:[^()]|\([^()]*\))*\)`, "''")

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

_validated(lines, j, i, v) if {
	re := _validator_re(v)
	some k in numbers.range(j, i)
	regex.match(re, lines[k])
}

_tainted(lines, i, v) if {
	j := _origin(lines, i, v)
	rhs := _rhs(lines[j])
	not regex.match(_sanitiser_re, rhs)
	regex.match(_source_re, rhs)
	not _validated(lines, j + 1, i, v)
}

_tainted(lines, i, v) if {
	j := _origin(lines, i, v)
	rhs := _unescaped(_rhs(lines[j]))
	not regex.match(_source_re, rhs)
	not regex.match(`^\s*(ldap_escape|intval|filter_var)\s*\(`, rhs)
	some w in _vars(rhs)
	k := _origin(lines, j, w)
	rhs2 := _rhs(lines[k])
	not regex.match(_sanitiser_re, rhs2)
	regex.match(_source_re, rhs2)
	not _validated(lines, k + 1, i, w)
}

# The statement starting at line i (the call may span several lines).
_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 8])
	joined := concat(" ", array.slice(lines, i, end + 1))
	s := split(joined, ";")[0]
}

_reaches(_, _, s) if regex.match(_source_re, _unescaped(s))

_reaches(lines, i, s) if {
	some v in _vars(_unescaped(s))
	_tainted(lines, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`ldap_(search|list|read)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ldap_")
	not helpers.is_comment_line(line)
	code := _no_strings(line)
	regex.match(_sink_re, code)
	stmt := _stmt(lines, i)
	call := substring(stmt, indexof(stmt, "ldap_"), -1)
	_reaches(lines, i, call)
	finding := {
		"rule_id": metadata.id,
		"message": "LDAP injection: a request value reaches the ldap_search()/ldap_list()/ldap_read() filter or base DN unescaped; wrap it in ldap_escape($value, '', LDAP_ESCAPE_FILTER) (or LDAP_ESCAPE_DN for DN parts)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
