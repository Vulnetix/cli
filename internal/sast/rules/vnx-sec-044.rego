package vulnetix.rules.vnx_sec_044

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-044",
	"name": "Microsoft Teams webhook URL",
	"description": "Reports a complete Microsoft Teams incoming webhook URL written into a file: the current form (<tenant>.webhook.office.com/webhookb2/<group-guid>@<tenant-guid>/IncomingWebhook/<32-hex>/<guid>) and the legacy form (outlook.office.com or outlook.office365.com /webhook/.../IncomingWebhook/...). Anyone holding the URL can post into the channel. The snippet is redacted. Not reported: truncated URLs, placeholder GUIDs and hashes (all zeros, xxxx, EXAMPLE), URLs read from the environment, Power Automate workflow URLs, and test, fixture and vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-044/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "teams", "webhook", "credentials"],
}

_guid := `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

_pattern := concat("", [
	`(?i:https?://(?:[a-z0-9-]+\.webhook\.office\.com/webhookb2|outlook\.office(?:365)?\.com/webhook))/`,
	`(`, _guid, `)@`, _guid, `/IncomingWebhook/([0-9a-fA-F]{32})/(`, _guid, `)`,
])

# lib secrets.skip_path knows *_test.py but not pytest's other spelling,
# test_*.py (or conftest.py), so a pytest module was scanned as production.
_pytest_file(path) if {
	parts := split(path, "/")
	base := parts[count(parts) - 1]
	startswith(base, "test_")
	endswith(base, ".py")
}

_pytest_file(path) if endswith(concat("", ["/", path]), "/conftest.py")

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not _pytest_file(path)
	contains(content, "IncomingWebhook/")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "IncomingWebhook/")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	not secrets.is_example_token(m[0][1])
	not secrets.is_example_token(m[0][2])
	not secrets.is_example_token(m[0][3])
	finding := {
		"rule_id": metadata.id,
		"message": "Microsoft Teams webhook URL found; rotate the webhook in your Teams channel configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
