package vulnetix.rules.vnx_sec_011

import rego.v1

metadata := {
	"id": "VNX-SEC-011",
	"name": "Hardcoded JWT token",
	"description": "A hardcoded JSON Web Token was found in source code. JWTs often contain session data and claims; committing them exposes authentication material in version history.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-011/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["secrets", "jwt", "token", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded JWT found; use environment variables or a secrets manager for tokens",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
