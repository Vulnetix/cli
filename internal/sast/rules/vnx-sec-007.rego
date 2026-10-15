package vulnetix.rules.vnx_sec_007

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-007",
	"name": "Slack token or webhook",
	"description": "Reports a hard-coded Slack credential in any file: a bot, user, workspace, refresh or legacy token (xoxb-, xoxp-, xoxa-, xoxo-, xoxr-, xoxs- followed by a numeric team/user id and a secret segment) and an incoming-webhook or workflow URL (https://hooks.slack.com/services/T…/B…/<secret>, /workflows/T…/A…/<id>/<secret>, /triggers/T…/<id>/<secret>). Not reported: Slack's documented example webhook (T00000000/B00000000/XXXX…) and other placeholder runs, tokens without a numeric id (xoxb-your-token), a webhook base URL built from configuration, prefix lists, environment references, and test, fixture, vendored and generated files. Configuration-refresh (xoxe-) and app-level (xapp-) tokens are VNX-SEC-419/420/421.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-007/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "slack", "credentials"],
}

_token := `(?:^|[^A-Za-z0-9_-])(xox[abposr]-[0-9]{8,14}-[0-9A-Za-z-]{20,})`

_webhook := `https://hooks\.slack\.com/(?:services|workflows|triggers)/(T[A-Z0-9]{8,12})/(B[A-Z0-9]{8,12}|A[A-Z0-9]{8,12}/[0-9]{8,20}|[0-9]{8,14})/([A-Za-z0-9]{20,})`

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`xox[abposr]-[0-9]{8}`, content)
	not secrets.skip_path(path)
	not _test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "xox")
	some m in regex.find_all_string_submatch_n(_token, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Slack token found; revoke it (auth.revoke or the app's OAuth settings) and load it from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "hooks.slack.com/")
	not secrets.skip_path(path)
	not _test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "hooks.slack.com/")
	some m in regex.find_all_string_submatch_n(_webhook, line, -1)
	not regex.match(`^T0+$`, m[1])
	not secrets.is_example_token(m[3])
	secrets.high_entropy(m[3], 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Slack webhook URL found; anyone holding it can post to the channel. Regenerate it in the app's Incoming Webhooks settings and load it from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

# Test code beyond helpers.is_test_path: Jest __mocks__ directories and Xcode
# test targets (AppTests/, FooTests.swift), which hold fake credentials.
_test_path(path) if helpers.is_test_path(path)

_test_path(path) if regex.match(`(^|/)(__mocks__|[A-Za-z0-9_]*Tests)/|Tests?\.swift$`, path)
