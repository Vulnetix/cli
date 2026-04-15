package vulnetix.rules.vnx_jwt_003

import rego.v1

metadata := {
	"id": "VNX-JWT-003",
	"name": "JWT signing with hardcoded secret",
	"description": "jwt.sign() or jwt.encode() uses a hardcoded string literal as the signing secret. If the secret is committed to source control, any party with repository access can forge valid tokens.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-003/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["jwt", "secrets", "credentials"],
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
	regex.match(`jwt\.sign\s*\(\s*[^,]+,\s*["'][^"']{8,}["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.sign() uses a hardcoded string secret; load the secret from an environment variable or secrets manager",
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
	regex.match(`jwt\.encode\s*\(\s*[^,]+,\s*["'][^"']{8,}["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "jwt.encode() uses a hardcoded string secret; load the secret from an environment variable or secrets manager",
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
	regex.match(`(JWT_SECRET|jwt_secret|secret_key)\s*[=:]\s*["'][^"']{8,}["']`, line)
	not contains(line, "os.environ")
	not contains(line, "process.env")
	finding := {
		"rule_id": metadata.id,
		"message": "JWT secret key is hardcoded; use an environment variable or secrets manager to store signing keys",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
