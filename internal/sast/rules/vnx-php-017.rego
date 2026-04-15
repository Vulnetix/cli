package vulnetix.rules.vnx_php_017

import rego.v1

metadata := {
	"id": "VNX-PHP-017",
	"name": "PHP LDAP injection via user-controlled filter",
	"description": "ldap_search() is called with a filter string that concatenates user-controlled input from superglobals. This allows attackers to modify the LDAP filter logic, potentially bypassing authentication or exfiltrating directory data. Use ldap_escape() with LDAP_ESCAPE_FILTER on all user inputs before inserting into LDAP filter strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-017/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [90],
	"capec": ["CAPEC-136"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ldap-injection", "injection", "php"],
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
	regex.match(`ldap_search\s*\(`, line)
	regex.match(`\$_(GET|POST|REQUEST|COOKIE)\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "LDAP injection: user input concatenated into ldap_search() filter — use ldap_escape($input, '', LDAP_ESCAPE_FILTER) on all user inputs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
