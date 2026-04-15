package vulnetix.rules.vnx_sec_030

import rego.v1

metadata := {
	"id": "VNX-SEC-030",
	"name": "Google OAuth client secret hardcoded",
	"description": "A Google OAuth 2.0 client secret (GOCSPX- prefix) appears hardcoded in source code. This secret is used with a client ID to authenticate OAuth 2.0 flows. Exposure allows impersonation of the application and token theft. Rotate at console.cloud.google.com/apis/credentials and store in a secrets manager.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-030/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "google", "oauth", "credentials"],
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
	regex.match(`GOCSPX-[0-9A-Za-z\-_]{28}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Google OAuth client secret detected — rotate at console.cloud.google.com/apis/credentials and store in a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
