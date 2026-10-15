package vulnetix.rules.vnx_sec_005

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-005",
	"name": "GCP API key",
	"description": "Reports a hard-coded Google Cloud / Google Maps / Firebase API key: a standalone 39-character token, AIza followed by 35 URL-safe base64 characters, in any file, including script URLs (?key=AIza…), Android string resources, Firebase web config and .env files. Not reported: placeholder runs (AIzaXXXX…), the AIza prefix inside a longer token, prefix checks, environment references, and test, fixture, vendored and generated files. Firebase web keys are designed to ship to browsers, but an unrestricted key still bills the project, so they are reported; restrict the key by API and referrer.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-005/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "gcp", "credentials"],
}

_token := `(?:^|[^A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?:[^A-Za-z0-9_-]|$)`

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "AIza")
	not secrets.skip_path(path)
	not _test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "AIza")
	some m in regex.find_all_string_submatch_n(_token, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Google API key found; restrict or regenerate it in Google Cloud Console > APIs & Services > Credentials, and load it from configuration outside the repository",
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
