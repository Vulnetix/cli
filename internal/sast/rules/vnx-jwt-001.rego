package vulnetix.rules.vnx_jwt_001

import rego.v1

metadata := {
	"id": "VNX-JWT-001",
	"name": "JWT signature verification disabled",
	"description": "JWT decode is called with verify_signature=False, options={verify_signature: False}, or equivalent. This allows any forged or tampered token to be accepted, completely bypassing authentication.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-001/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [347],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["jwt", "authentication", "broken-auth"],
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
	regex.match(`jwt\.decode\s*\(.*verify_signature.*False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "JWT signature verification disabled (verify_signature=False); remove this option to enforce token integrity checks",
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
	regex.match(`jwt\.decode\s*\(.*verify\s*=\s*False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "JWT verification disabled (verify=False); always verify JWT signatures in production code",
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
	regex.match(`algorithms\s*[:=]\s*\[.*["\']none["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "JWT 'none' algorithm permitted; this allows unsigned tokens that bypass authentication entirely — remove 'none' from the algorithms list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
