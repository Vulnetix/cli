package vulnetix.rules.vnx_php_009

import rego.v1

metadata := {
	"id": "VNX-PHP-009",
	"name": "PHP preg_replace with /e modifier",
	"description": "The /e modifier in preg_replace() evaluates the replacement string as PHP code, enabling remote code execution. This modifier was deprecated in PHP 5.5 and removed in PHP 7.0.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-009/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["rce", "code-injection", "deprecated", "php"],
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
	regex.match(`preg_replace\s*\(\s*['"][/#][^'"]*[/#][a-z]*e`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "preg_replace() with /e modifier executes replacement as PHP code; use preg_replace_callback() instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
