package vulnetix.rules.vnx_php_006

import rego.v1

metadata := {
	"id": "VNX-PHP-006",
	"name": "PHP object injection via unserialize",
	"description": "Using unserialize() on user-controlled data enables PHP object injection, allowing attackers to execute arbitrary code through crafted serialized objects.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-006/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["deserialization", "object-injection", "php"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_unserialize_indicators := {
	"unserialize($_GET",
	"unserialize($_POST",
	"unserialize($_REQUEST",
	"unserialize($_COOKIE",
	"maybe_unserialize($_GET",
	"maybe_unserialize($_POST",
	"maybe_unserialize($_REQUEST",
	"maybe_unserialize($_COOKIE",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _unserialize_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input passed to unserialize(); use json_decode() or set allowed_classes to false",
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
	regex.match(`\bunserialize\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "unserialize() can execute arbitrary code; prefer json_decode() or set allowed_classes parameter",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
