package vulnetix.rules.vnx_sec_049

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-049",
	"name": "Anthropic admin API key",
	"description": "Reports a complete Anthropic Admin API key: the sk-ant-admin01- prefix followed by the 93-character body and the AA terminator, in any file (source, .env, YAML, shell). Admin keys manage an organisation's members, workspaces, billing and other API keys. Not reported: a prefix on its own, a truncated key, placeholder bodies (xxxx, your-key-here), keys in test, fixture, vendored or generated paths, and ordinary sk-ant-api03- workspace keys, which are a different credential.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-049/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "anthropic", "ai", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_-])(sk-ant-admin01-[A-Za-z0-9_-]{93}AA)(?:[^A-Za-z0-9_-]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "sk-ant-admin01-")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "sk-ant-admin01-")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(substring(token, 15, -1))
	finding := {
		"rule_id": metadata.id,
		"message": "Anthropic admin API key found; revoke it in the Anthropic console (Settings > Admin keys) and audit organisation changes made with it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
