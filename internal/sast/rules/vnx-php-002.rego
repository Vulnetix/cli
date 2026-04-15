package vulnetix.rules.vnx_php_002

import rego.v1

metadata := {
	"id": "VNX-PHP-002",
	"name": "Dangerous function in PHP",
	"description": "Functions like eval(), exec(), system(), passthru(), and shell_exec() execute arbitrary commands. If any argument is user-controlled, this enables remote code execution.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PHP-002",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["command-injection", "code-injection", "dangerous-function"],
}

_is_php(path) if endswith(path, ".php")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_php(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Dangerous function call; avoid exec/system/passthru/shell_exec or sanitize inputs with escapeshellarg()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
