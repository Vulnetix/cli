package vulnetix.rules.vnx_node_019

import rego.v1

metadata := {
	"id": "VNX-NODE-019",
	"name": "Hardcoded JWT or session secret",
	"description": "A hardcoded string literal is used as the secret for JWT signing or express-session configuration. Hardcoded secrets are visible to anyone with source code access and cannot be rotated without a code change. Store secrets in environment variables or a secrets manager and access them at runtime.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-019/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["hardcoded-secret", "jwt", "session", "credentials", "node"],
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
	regex.match(`jwt\.(sign|verify)\s*\(`, line)
	regex.match(`['"][^'"]{4,}['"]`, line)
	not contains(line, "process.env")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded string literal passed as JWT secret to jwt.sign/verify; store the secret in an environment variable (e.g. process.env.JWT_SECRET)",
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
	contains(line, "secret:")
	regex.match(`secret\s*:\s*['"][^'"]{4,}['"]`, line)
	not contains(line, "process.env")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded string literal used as session/JWT secret; store the secret in an environment variable (e.g. process.env.SESSION_SECRET)",
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
	contains(line, "createHmac")
	regex.match(`createHmac\s*\(\s*['"][^'"]+['"],\s*['"][^'"]{4,}['"]`, line)
	not contains(line, "process.env")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded HMAC key detected in crypto.createHmac(); store cryptographic keys in environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
