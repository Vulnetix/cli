package vulnetix.rules.vnx_sec_014

import rego.v1

metadata := {
	"id": "VNX-SEC-014",
	"name": "Hardcoded password in variable",
	"description": "A variable named password, passwd, or secret is assigned a string literal, indicating a hardcoded credential that should be moved to environment variables or a secrets manager.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-014/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798, 259],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["secrets", "password", "credentials", "hardcoded"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")
_skip(path) if endswith(path, ".txt")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)(password|passwd|db_password|admin_password|root_password|mysql_pwd|secret_key)\s*=\s*["'][^"']{8,}["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded password found; use environment variables or a secrets manager",
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
	regex.match(`(?i)["'](password|passwd|secret_key|db_password|admin_password)["']\s*:\s*["'][^"']{8,}["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded password found; use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
