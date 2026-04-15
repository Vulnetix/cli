package vulnetix.rules.vnx_sec_012

import rego.v1

metadata := {
	"id": "VNX-SEC-012",
	"name": "CORS wildcard or origin reflection",
	"description": "Setting Access-Control-Allow-Origin to '*' or reflecting the request origin without validation allows any website to read responses, potentially exposing sensitive data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-012/",
	"languages": [],
	"severity": "high",
	"level": "warning",
	"kind": "open",
	"cwe": [942],
	"capec": ["CAPEC-111"],
	"attack_technique": ["T1189"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cors", "misconfiguration", "web"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_cors_indicators := {
	"Access-Control-Allow-Origin: *",
	"Access-Control-Allow-Origin\", \"*\"",
	"Access-Control-Allow-Origin', '*'",
	"allowedOrigins(\"*\")",
	"AllowAllOrigins: true",
	"allow_origins=[\"*\"]",
	"origin: '*'",
	"origin: \"*\"",
	"cors({origin: true})",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _cors_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "CORS allows all origins; restrict to specific trusted domains",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
