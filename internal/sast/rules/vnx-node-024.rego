package vulnetix.rules.vnx_node_024

import rego.v1

metadata := {
	"id": "VNX-NODE-024",
	"name": "postMessage without origin validation (CSWSH/XSS)",
	"description": "window.addEventListener('message', ...) is registered without checking event.origin in the handler. Any window that can embed or navigate to this page can post arbitrary messages that the handler will process, enabling cross-origin data injection, CSRF, or XSS. Always validate event.origin against an expected value before processing the message.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-024/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [345],
	"capec": ["CAPEC-111"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["postmessage", "origin-validation", "xss", "browser", "node"],
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
	contains(line, "addEventListener")
	contains(line, "'message'")
	not contains(line, ".origin")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "addEventListener('message') handler does not appear to check event.origin; validate origin against an allowlist before processing postMessage data",
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
	contains(line, `postMessage`)
	contains(line, `"*"`)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "postMessage called with wildcard target origin '*'; specify the exact target origin to prevent message interception by malicious frames",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
