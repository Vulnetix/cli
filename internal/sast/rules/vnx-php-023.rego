package vulnetix.rules.vnx_php_023

import rego.v1

metadata := {
	"id": "VNX-PHP-023",
	"name": "PHP anonymous LDAP bind without password",
	"description": "ldap_bind() is called without a password argument, with NULL, or with an empty string. Anonymous LDAP binds allow unauthenticated access to the directory, potentially exposing user data, credentials, or organisational information. Always bind with a dedicated service account DN and a strong password stored in an environment variable or secrets manager.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-023/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [287],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1078.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ldap", "anonymous-bind", "authentication", "php"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "ldap_bind")
	regex.match(`ldap_bind\s*\(\s*\$\w+\s*,\s*\$\w+\s*,\s*(NULL|null|''|"")`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "ldap_bind() called with empty or null password; anonymous LDAP bind exposes the directory to unauthenticated access — bind with a service account and strong password",
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
	regex.match(`ldap_bind\s*\(\s*\$\w+\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "ldap_bind() called without a password argument; this performs an anonymous bind — provide a DN and password for authenticated access",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
