package vulnetix.rules.vnx_node_002

import rego.v1

metadata := {
	"id": "VNX-NODE-002",
	"name": "eval() or new Function() in JavaScript",
	"description": "eval() and new Function() execute arbitrary JavaScript code. If any part of the argument is user-controlled, this enables remote code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-002/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-35"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["code-injection", "dangerous-function"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\beval\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "eval() can execute arbitrary code; avoid dynamic code evaluation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new\s+Function\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "new Function() can execute arbitrary code; avoid dynamic code construction",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
