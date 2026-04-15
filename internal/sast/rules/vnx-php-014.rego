package vulnetix.rules.vnx_php_014

import rego.v1

metadata := {
	"id": "VNX-PHP-014",
	"name": "PHP session fixation via user-controlled session ID",
	"description": "session_id() is called with user-controlled input from $_GET, $_POST, $_REQUEST, or $_COOKIE. This allows an attacker to fix the session ID before the victim authenticates, enabling session hijacking. Never accept session IDs from user input; call session_regenerate_id(true) after login.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-014/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [384],
	"capec": ["CAPEC-61"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["session-fixation", "authentication", "php"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`session_id\s*\(`, line)
	regex.match(`\$_(GET|POST|REQUEST|COOKIE)\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Session fixation: user-controlled input passed to session_id() allows attackers to hijack sessions — never accept session IDs from user input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
