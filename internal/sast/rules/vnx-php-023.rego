package vulnetix.rules.vnx_php_023

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-023",
	"name": "PHP anonymous LDAP bind without password",
	"description": "ldap_bind() or ldap_bind_ext() performs an anonymous or unauthenticated bind: it is called with the link only, with a null DN, without a password argument, or with a password of null, '' or \"\" (literally or through a variable assigned that value in the 25 lines above), or a login passes a request password ($_POST, $_GET, $_REQUEST, a Laravel/Symfony request accessor, inline or through a variable) to ldap_bind() with no empty-value check (empty(), strlen(), === '', a 'required' validation rule) between where it was read and the bind. LDAP servers accept a DN with an empty password as an unauthenticated bind that succeeds, so a login that only tests ldap_bind()'s result lets anyone in with any user name and a blank password. Not reported: binds with a service-account password from getenv(), configuration or a secrets store, binds whose password origin is not visible in the file, ldap_sasl_bind() (SASL EXTERNAL uses a client certificate), object methods named bind(), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-023/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [287],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1078.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ldap", "anonymous-bind", "authentication", "php"],
}

_arg := `(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\((?:[^()'"]|'[^']*'|"[^"]*"|\([^()]*\))*\)|\[[^\[\]]*\]|[^,'"()\[\]])+`

_bind_re := concat("", [`^ldap_bind(?:_ext)?\s*\(\s*(`, _arg, `)\s*(?:,\s*(`, _arg, `)\s*)?(?:,\s*(`, _arg, `)\s*)?[,)]`])

_sink_re := `(^|[^\w$>:\\])ldap_bind(_ext)?\s*\(`

_empty_lit := `^(?:''|""|(?i:null))$`

_source_re := `\$_(GET|POST|REQUEST|COOKIE)\b|\$request\s*->\s*(input|get|query|post|string)\s*\(|\$request\s*->\s*(query|request)\s*->\s*get\s*\(|\bRequest::(input|get|post)\s*\(|\brequest\(\s*\)\s*->\s*(input|get|post)\s*\(|\brequest\(\s*['"]|\bInput::get\s*\(|\bfilter_input\s*\(\s*INPUT_(GET|POST|REQUEST)`

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 6])
	joined := concat(" ", array.slice(lines, i, end + 1))
	s := substring(joined, indexof(joined, "ldap_bind"), -1)
}

_origin(lines, i, v) := j if {
	re := concat("", [`^\s*\$`, v, `\s*=[^=>]`])
	cands := [k |
		some k in numbers.range(max([0, i - 25]), i - 1)
		k < i
		regex.match(re, lines[k])
	]
	count(cands) > 0
	j := max(cands)
}

_rhs(line) := trim_space(regex.replace(line, `^\s*\$\w+\s*=`, ""))

_var(a) := v if {
	m := regex.find_all_string_submatch_n(`^\$([A-Za-z_]\w*)$`, a, 1)
	count(m) > 0
	v := m[0][1]
}

# ── Anonymous / unauthenticated bind ─────────────────────────────────────
_anonymous(_, _, dn, _) if dn == ""

_anonymous(_, _, dn, _) if regex.match(`^(?i:null)$`, dn)

_anonymous(_, _, dn, pw) if {
	dn != ""
	pw == ""
}

_anonymous(_, _, _, pw) if regex.match(_empty_lit, pw)

_anonymous(lines, i, _, pw) if {
	v := _var(pw)
	j := _origin(lines, i, v)
	regex.match(`^(?:''|""|(?i:null))\s*;`, _rhs(lines[j]))
}

# ── Login with a request password and no empty check ─────────────────────
_empty_check(v) := concat("", [
	`\b(empty|strlen|mb_strlen|trim|blank|filled)\s*\(\s*\$`, v, `\b`,
	`|\$`, v, `\s*(===?|!==?|<>)\s*(''|""|(?i:null|false))`,
	`|(''|""|(?i:null|false))\s*(===?|!==?)\s*\$`, v, `\b`,
	`|!\s*\$`, v, `\b|['"]required\b`,
])

_unchecked_request(_, _, pw, stmt) if {
	regex.match(_source_re, pw)
	not regex.match(`\b(empty|strlen|filled)\s*\(`, stmt)
}

_unchecked_request(lines, i, pw, stmt) if {
	v := _var(pw)
	j := _origin(lines, i, v)
	regex.match(_source_re, _rhs(lines[j]))
	re := _empty_check(v)
	not _checked(lines, j, i, re)
	not regex.match(re, stmt)
}

_checked(lines, j, i, re) if {
	some k in numbers.range(j, i)
	regex.match(re, lines[k])
}

_bind_args(lines, i) := [dn, pw, stmt] if {
	stmt := _stmt(lines, i)
	m := regex.find_all_string_submatch_n(_bind_re, stmt, 1)
	count(m) > 0
	dn := trim_space(m[0][2])
	pw := trim_space(m[0][3])
}

_sinks(content) := [i |
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ldap_bind")
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _no_strings(line))
]

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "ldap_bind")
	lines := split(content, "\n")
	some i in _sinks(content)
	[dn, pw, _] := _bind_args(lines, i)
	_anonymous(lines, i, dn, pw)
	finding := {
		"rule_id": metadata.id,
		"message": "ldap_bind() binds anonymously or with an empty password, so the connection is unauthenticated; bind with a service-account DN and a password read from the environment or a secrets store",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "ldap_bind")
	regex.match(`\$_(GET|POST|REQUEST)\b|request|Input::|filter_input`, content)
	lines := split(content, "\n")
	some i in _sinks(content)
	[dn, pw, stmt] := _bind_args(lines, i)
	not _anonymous(lines, i, dn, pw)
	_unchecked_request(lines, i, pw, stmt)
	finding := {
		"rule_id": metadata.id,
		"message": "A request password reaches ldap_bind() without an empty-value check; an empty password makes an unauthenticated bind that succeeds, so any user name logs in with a blank password; reject empty passwords before binding",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
