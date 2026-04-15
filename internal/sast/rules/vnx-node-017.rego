package vulnetix.rules.vnx_node_017

import rego.v1

metadata := {
	"id": "VNX-NODE-017",
	"name": "Deserialization of untrusted data via node-serialize or serialize-to-js",
	"description": "The application calls unserialize() or deserialize() from node-serialize or serialize-to-js with user-controlled data. These libraries execute embedded JavaScript IIFE expressions during deserialization, allowing remote code execution. Use JSON.parse() for safe deserialization of untrusted data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-017/",
	"languages": ["javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["deserialization", "rce", "node-serialize", "node"],
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
	contains(line, "node-serialize")
	finding := {
		"rule_id": metadata.id,
		"message": "Detected import of node-serialize; calling unserialize() with untrusted data enables remote code execution via embedded IIFE — use JSON.parse() instead",
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
	contains(line, "serialize-to-js")
	regex.match(`(unserialize|deserialize)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Detected serialize-to-js deserialize() call; passing untrusted data enables remote code execution — use JSON.parse() instead",
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
	regex.match(`\.(unserialize|deserialize)\s*\(`, line)
	regex.match(`req\.(body|query|params)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "unserialize/deserialize called with request data; this enables remote code execution if the input came from node-serialize — use JSON.parse() for safe deserialization",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
