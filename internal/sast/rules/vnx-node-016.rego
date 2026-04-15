package vulnetix.rules.vnx_node_016

import rego.v1

metadata := {
	"id": "VNX-NODE-016",
	"name": "ReDoS via user-controlled regular expression",
	"description": "User-controlled input from the HTTP request is passed directly to the RegExp constructor or used in string.match(). An attacker can supply a malicious pattern with catastrophic backtracking to freeze the event loop (ReDoS).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-016/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1333],
	"capec": ["CAPEC-197"],
	"attack_technique": ["T1499.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["redos", "regex", "dos"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "new RegExp(")
	regex.match(`req\.(query|body|params)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input passed to RegExp constructor; this enables ReDoS attacks — use a fixed pattern or a safe regex library",
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
	regex.match(`\.(match|search)\s*\(\s*req\.(query|body|params)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "String.match/search called with user-controlled pattern; this enables ReDoS attacks — always use fixed regex patterns",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
