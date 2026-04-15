package vulnetix.rules.vnx_sec_006

import rego.v1

metadata := {
	"id": "VNX-SEC-006",
	"name": "Stripe secret key",
	"description": "A Stripe secret API key (sk_live or sk_test prefix) was found in source code. Secret keys grant full access to the Stripe account including payment operations.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-006/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "stripe", "payment", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`sk_(live|test)_[0-9a-zA-Z]{24,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Stripe secret key found; rotate the key and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
