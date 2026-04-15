package vulnetix.rules.vnx_sec_015

import rego.v1

metadata := {
	"id": "VNX-SEC-015",
	"name": "JWT algorithm none attack",
	"description": "Setting JWT algorithm to 'none' disables signature verification, allowing attackers to forge arbitrary tokens.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-015/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [345, 327],
	"capec": ["CAPEC-115"],
	"attack_technique": ["T1550.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["jwt", "authentication", "token"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_jwt_none_indicators := {
	"algorithm=\"none\"",
	"algorithm='none'",
	"algorithms=[\"none\"]",
	"algorithms=['none']",
	"\"alg\": \"none\"",
	"\"alg\":\"none\"",
	"'alg': 'none'",
	"Algorithm.NONE",
	"SignatureAlgorithm.NONE",
	"JWSAlgorithm.parse(\"none\")",
	"algorithm: \"none\"",
	"algorithm: 'none'",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _jwt_none_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "JWT configured with algorithm 'none'; always require a strong signing algorithm (RS256, ES256)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
