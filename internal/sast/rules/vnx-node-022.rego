package vulnetix.rules.vnx_node_022

import rego.v1

metadata := {
	"id": "VNX-NODE-022",
	"name": "Shell injection via shelljs exec()",
	"description": "shelljs.exec() or shell.exec() is called with a variable argument rather than a string literal. If the argument contains user-controlled data, an attacker can inject shell metacharacters to execute arbitrary commands. Use execFile() with a fixed command and separate argument array, or validate and escape all user input with a strict allowlist.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-022/",
	"languages": ["javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["command-injection", "shelljs", "rce", "node"],
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
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "shelljs")
	contains(line, "require(")
	finding := {
		"rule_id": metadata.id,
		"message": "shelljs imported; ensure shell.exec() is never called with user-controlled data to prevent command injection",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(exec|execSync)\s*\(`, line)
	regex.match(`req\.(body|query|params|headers)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "shell exec() called with request-derived data; this allows command injection — use execFile() with a fixed command and argument array instead",
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
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`shell\.exec\s*\(`, line)
	not regex.match(`shell\.exec\s*\(\s*["']`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "shell.exec() called with non-literal argument; if this value is user-controlled it enables command injection — use a fixed command string or execFile() with argument array",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
