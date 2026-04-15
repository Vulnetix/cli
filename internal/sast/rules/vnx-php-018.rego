package vulnetix.rules.vnx_php_018

import rego.v1

metadata := {
	"id": "VNX-PHP-018",
	"name": "PHP sensitive debug output disclosure",
	"description": "var_dump(), print_r(), or var_export() is called with sensitive superglobals ($_SESSION, $_SERVER, $_ENV). This exposes session tokens, server paths, environment variables, and credentials to the response. Remove all debug output from production code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-018/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [200],
	"capec": ["CAPEC-118"],
	"attack_technique": ["T1082"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["information-disclosure", "debug", "php"],
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
	regex.match(`var_dump\s*\(`, line)
	regex.match(`\$_(SESSION|SERVER|ENV)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Information disclosure: var_dump() of $_SESSION/$_SERVER/$_ENV exposes credentials and server configuration — remove debug output from production",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`print_r\s*\(`, line)
	regex.match(`\$_(SESSION|SERVER|ENV)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Information disclosure: print_r() of $_SESSION/$_SERVER/$_ENV exposes credentials and server configuration — remove debug output from production",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`var_export\s*\(`, line)
	regex.match(`\$_(SESSION|SERVER|ENV)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Information disclosure: var_export() of $_SESSION/$_SERVER/$_ENV exposes credentials and server configuration — remove debug output from production",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
