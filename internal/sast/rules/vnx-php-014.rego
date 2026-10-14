package vulnetix.rules.vnx_php_014

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-014",
	"name": "PHP session fixation via user-controlled session ID",
	"description": "The session identifier is taken from the request, so an attacker can plant a known ID on a victim and use it after the victim logs in. Reported: session_id() called with a $_GET/$_POST/$_REQUEST/$_COOKIE element (including $_COOKIE[session_name()], which accepts any client-chosen cookie value as the ID) or with a variable assigned from one within the 15 lines above; and ini_set() turning on session.use_trans_sid (IDs accepted from the URL) or turning off session.use_only_cookies or session.use_strict_mode (uninitialised IDs accepted). Not reported: session_id() as a getter, session_id() given a generated value (random_bytes(), session_create_id()), the settings set to their safe values, and the call inside a comment or a string literal. A login that never calls session_regenerate_id() is not detected: whether a handler authenticates cannot be told line by line.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-014/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [384],
	"capec": ["CAPEC-61"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["session-fixation", "authentication", "php"],
}

_source_re := `\$_(GET|POST|REQUEST|COOKIE)\b`

_lit_re := `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

_code(line) := regex.replace(line, _lit_re, `''`)

_args(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bsession_id\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, line, 1)
	count(m) > 0
}

_tainted(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	regex.match(_source_re, prev)
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, prev, 1)
	v := m[0][1]
}

_fixes(lines, i) if {
	regex.match(`\bsession_id\s*\(`, _code(lines[i]))
	args := _args(lines[i])
	regex.match(_source_re, args)
}

_fixes(lines, i) if {
	regex.match(`\bsession_id\s*\(`, _code(lines[i]))
	args := _args(lines[i])
	some v in _tainted(lines, i)
	regex.match(concat("", [`^\s*\$`, v, `\s*$`]), args)
}

_fixes(lines, i) if regex.match(`(?i)\bini_set\s*\(\s*['"]session\.use_trans_sid['"]\s*,\s*(['"]?(1|on|true)['"]?|true)\s*\)`, lines[i])

_fixes(lines, i) if regex.match(`(?i)\bini_set\s*\(\s*['"]session\.(use_only_cookies|use_strict_mode)['"]\s*,\s*(['"]?(0|off|false)?['"]?|false)\s*\)`, lines[i])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`session_id\s*\(|session\.use_`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`session_id|session\.use_`, line)
	not helpers.is_comment_line(line)
	_fixes(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Session fixation: the session ID can be chosen by the client; never take it from the request, keep use_only_cookies and use_strict_mode on, and call session_regenerate_id(true) after login",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
