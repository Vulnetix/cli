package vulnetix.rules.vnx_php_008

import rego.v1

metadata := {
	"id": "VNX-PHP-008",
	"name": "PHP phpinfo exposure",
	"description": "phpinfo() discloses detailed server configuration, installed modules, environment variables, and file paths that assist attackers in reconnaissance.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-008/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-54"],
	"attack_technique": ["T1592"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["information-disclosure", "reconnaissance", "php"],
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
	regex.match(`\bphpinfo\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "phpinfo() exposes server configuration details; remove from production code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
