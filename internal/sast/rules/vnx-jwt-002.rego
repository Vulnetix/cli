package vulnetix.rules.vnx_jwt_002

import rego.v1

metadata := {
	"id": "VNX-JWT-002",
	"name": "JWT token signed without expiration",
	"description": "jwt.sign() or jwt.encode() is called without an expiresIn / exp claim. Tokens without expiration remain valid indefinitely, increasing the blast radius of any token leak.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-002/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [613],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["jwt", "session-management", "authentication"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "jwt.sign(")
	not contains(line, "expiresIn")
	not contains(line, "exp:")
	not contains(line, "exp :")
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.sign() called without expiresIn option; tokens without expiration remain valid indefinitely — add expiresIn (e.g. '15m' or '1h')",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "jwt.encode(")
	not contains(line, "exp")
	not contains(line, "expires")
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.encode() called without an exp claim; tokens without expiration remain valid indefinitely — add an exp field to the payload",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
