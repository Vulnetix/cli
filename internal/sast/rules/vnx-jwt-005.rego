package vulnetix.rules.vnx_jwt_005

import rego.v1

metadata := {
	"id": "VNX-JWT-005",
	"name": "Sensitive credential data stored in JWT payload",
	"description": "A JWT payload contains a 'password' or 'secret' key. JWT payloads are only base64-encoded, not encrypted, and can be trivially decoded by anyone who holds the token. Never store passwords, secrets, or other sensitive credentials in JWT claims; store only non-sensitive identifiers such as user IDs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-005/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [522],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["jwt", "credentials", "sensitive-data", "authentication"],
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
	regex.match(`["']password["']\s*:\s*`, line)
	regex.match(`jwt\.(encode|sign)`, lines[_])
	finding := {
		"rule_id": metadata.id,
		"message": "JWT payload contains a 'password' key; JWT payloads are not encrypted and can be decoded by anyone holding the token — store only non-sensitive identifiers in JWT claims",
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
	regex.match(`(jwt\.encode|jwt\.sign)\s*\(\s*\{[^}]*["']password["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.encode()/jwt.sign() payload contains 'password'; JWT payloads are base64-encoded and visible to token holders — never store passwords in JWT claims",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
