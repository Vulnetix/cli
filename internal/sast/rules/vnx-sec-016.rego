package vulnetix.rules.vnx_sec_016

import rego.v1

metadata := {
	"id": "VNX-SEC-016",
	"name": "TLS verification disabled in shell command",
	"description": "Shell commands using curl -k/--insecure or wget --no-check-certificate skip TLS certificate validation, enabling man-in-the-middle attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-016/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tls", "curl", "wget", "shell"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_insecure_shell_indicators := {
	"curl -k ",
	"curl -k\"",
	"curl --insecure",
	"wget --no-check-certificate",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _insecure_shell_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "TLS verification disabled in shell command; remove -k/--insecure flag to enable certificate validation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
