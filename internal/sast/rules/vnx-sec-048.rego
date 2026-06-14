package vulnetix.rules.vnx_sec_048

import rego.v1

metadata := {
	"id": "VNX-SEC-048",
	"name": "OpenAI project / service / admin key",
	"description": "An OpenAI project, service account, or admin key (sk-proj-, sk-svcacct-, sk-admin- prefix) was found in source code. These keys grant access to OpenAI APIs and can incur significant cost or expose user data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-048/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "openai", "ai", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "OpenAI project/service/admin key found; revoke the key in the OpenAI dashboard",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
