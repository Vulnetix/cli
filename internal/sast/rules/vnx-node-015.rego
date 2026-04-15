package vulnetix.rules.vnx_node_015

import rego.v1

metadata := {
	"id": "VNX-NODE-015",
	"name": "WebSocket server without origin verification (CSWSH)",
	"description": "WebSocket.Server or Socket.IO server is created without origin validation. Without origin checking, the server is vulnerable to Cross-Site WebSocket Hijacking (CSWSH) where a malicious page can open a WebSocket connection using the victim's cookies.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-015/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1385],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["websocket", "cswsh", "origin-validation"],
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
	contains(line, "WebSocket.Server")
	not contains(line, "verifyClient")
	finding := {
		"rule_id": metadata.id,
		"message": "WebSocket.Server created without verifyClient callback; add a verifyClient function that validates the Origin header to prevent CSWSH attacks",
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
	regex.match(`cors\s*:\s*\{\s*origin\s*:\s*["']\*["']`, line)
	regex.match(`(io\(|new Server\()`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Socket.IO server configured with cors origin '*'; restrict to specific trusted domains to prevent CSWSH attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
