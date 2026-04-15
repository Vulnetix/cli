package vulnetix.rules.vnx_jwt_004

import rego.v1

metadata := {
	"id": "VNX-JWT-004",
	"name": "JWT algorithm explicitly set to 'none'",
	"description": "A JWT is encoded or decoded with algorithm='none', which disables cryptographic signing and allows any party to forge valid tokens by omitting the signature. Never use the 'none' algorithm in production; always specify a strong signing algorithm such as HS256, RS256, or ES256.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-004/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["jwt", "algorithm", "authentication", "none-alg"],
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
	regex.match(`jwt\.encode\s*\(.*algorithm\s*=\s*["']none["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.encode() uses algorithm='none' which produces unsigned tokens that any attacker can forge; specify a strong algorithm such as HS256 or RS256",
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
	regex.match(`jwt\.sign\s*\(.*algorithm\s*[:=]\s*["']none["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.sign() uses algorithm 'none' which produces unsigned tokens; use a strong algorithm such as HS256 or RS256",
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
	regex.match(`algorithms\s*[:=]\s*\[\s*["']none["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "JWT decode accepts 'none' as the sole permitted algorithm, allowing unsigned tokens; specify only strong signing algorithms in the algorithms list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
