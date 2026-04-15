package vulnetix.rules.vnx_jwt_006

import rego.v1

metadata := {
	"id": "VNX-JWT-006",
	"name": "JWT missing audience or issuer verification",
	"description": "JWT decode is called without verifying the 'aud' (audience) or 'iss' (issuer) claims. Without these checks, a token issued for one service can be replayed against another service that shares the same signing key. Always verify audience and issuer claims to prevent token cross-service replay attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-006/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [287],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["jwt", "authentication", "audience", "issuer"],
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
	regex.match(`jwt\.decode\s*\(`, line)
	not contains(line, "audience")
	not contains(line, "issuer")
	not contains(line, "aud")
	not contains(line, "iss")
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.decode() called without audience or issuer verification; tokens can be replayed across services — add audience= and issuer= parameters to validate token claims",
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
	regex.match(`jwt\.verify\s*\(`, line)
	not contains(line, "audience")
	not contains(line, "issuer")
	not contains(line, "aud")
	not contains(line, "iss")
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.verify() called without audience or issuer options; tokens can be replayed cross-service — add { audience: '...', issuer: '...' } to the options object",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
