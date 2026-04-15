package vulnetix.rules.vnx_php_010

import rego.v1

metadata := {
	"id": "VNX-PHP-010",
	"name": "PHP type juggling in comparison",
	"description": "Using loose comparison (== or !=) with user input in PHP can lead to authentication bypasses due to type juggling. PHP's magic hash vulnerability allows strings like '0e123' to equal 0.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-010/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [697],
	"capec": ["CAPEC-153"],
	"attack_technique": ["T1548"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["type-juggling", "authentication", "comparison", "php"],
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
	regex.match(`\$_(GET|POST|REQUEST|COOKIE)\[.*\]\s*==\s*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Loose comparison (==) with user input is vulnerable to type juggling; use strict comparison (===) instead",
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
	regex.match(`==\s*\$_(GET|POST|REQUEST|COOKIE)\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Loose comparison (==) with user input is vulnerable to type juggling; use strict comparison (===) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
