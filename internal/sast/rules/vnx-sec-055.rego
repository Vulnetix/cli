package vulnetix.rules.vnx_sec_055

import rego.v1

metadata := {
	"id": "VNX-SEC-055",
	"name": "New Relic API key",
	"description": "A New Relic API key (NRJS-, NRII-, NRAK- prefix) was found in source code. New Relic keys grant access to application performance data, browser monitoring, and insert APIs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-055/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "newrelic", "monitoring", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`NRJS-[a-f0-9]{19}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "New Relic browser API token found; revoke the token in the New Relic dashboard",
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
	regex.match(`NRII-[a-z0-9-]{32}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "New Relic insert key found; revoke the key in the New Relic dashboard",
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
	regex.match(`NRAK-[a-z0-9]{27}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "New Relic user API key found; revoke the key in the New Relic dashboard",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
