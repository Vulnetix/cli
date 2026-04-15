package vulnetix.rules.vnx_ruby_002

import rego.v1

metadata := {
	"id": "VNX-RUBY-002",
	"name": "eval() or system() in Ruby",
	"description": "eval(), Kernel.system(), and backtick execution can run arbitrary code. If any argument is user-controlled, this enables remote code execution.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-RUBY-002",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [94],
	"capec": ["CAPEC-35"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["code-injection", "command-injection", "dangerous-function"],
}

_is_rb(path) if endswith(path, ".rb")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rb(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\beval\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "eval() can execute arbitrary Ruby code; avoid dynamic evaluation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_rb(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bsystem\s*\(`, line)
	not contains(line, "operating_system")
	finding := {
		"rule_id": metadata.id,
		"message": "system() executes shell commands; use Open3.capture3 or an argument array for safety",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
