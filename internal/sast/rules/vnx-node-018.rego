package vulnetix.rules.vnx_node_018

import rego.v1

metadata := {
	"id": "VNX-NODE-018",
	"name": "JWT decoded without signature verification",
	"description": "jwt.decode() is used instead of jwt.verify(). The decode function does not validate the token signature, issuer, audience, or expiry. An attacker can craft or modify tokens with arbitrary payloads and they will be accepted. Always use jwt.verify() with the expected secret or public key.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-018/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["jwt", "authentication", "signature-bypass", "node"],
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
	regex.match(`jwt\.decode\s*\(`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.decode() does not verify the token signature; an attacker can forge tokens — use jwt.verify() with the correct secret/public key",
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
	regex.match(`jsonwebtoken`, line)
	contains(line, "algorithms")
	contains(line, "none")
	finding := {
		"rule_id": metadata.id,
		"message": "JWT configured to accept 'none' algorithm; this disables signature verification entirely and allows forged tokens — remove 'none' from accepted algorithms",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
