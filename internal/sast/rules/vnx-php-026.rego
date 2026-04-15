package vulnetix.rules.vnx_php_026

import rego.v1

metadata := {
	"id": "VNX-PHP-026",
	"name": "PHP session poisoning via user-controlled session key",
	"description": "A user-controlled value from $_GET, $_POST, $_REQUEST, or $_COOKIE is used as the key to write into $_SESSION. An attacker can control which session variable is written, overwriting trusted session state such as roles, authentication flags, or CSRF tokens. Never use user input as a $_SESSION key; always use hardcoded key names.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-026/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [284],
	"capec": ["CAPEC-61"],
	"attack_technique": ["T1565.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["session-poisoning", "session", "access-control", "php"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "$_SESSION[")
	regex.match(`\$_SESSION\s*\[\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input used as $_SESSION key; an attacker can overwrite arbitrary session variables — always use hardcoded string keys for $_SESSION",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "$_SESSION")
	regex.match(`\$_SESSION\s*\[\s*\$\w+\s*\]\s*=`, line)
	regex.match(`\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Variable derived from user input used as $_SESSION key; this may enable session poisoning — use only hardcoded string constants as session keys",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
