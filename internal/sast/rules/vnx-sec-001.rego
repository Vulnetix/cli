package vulnetix.rules.vnx_sec_001

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-001",
	"name": "AWS access key ID",
	"description": "Reports a hard-coded AWS access key ID: a standalone 20-character token with an AKIA (long-term user key), ASIA (STS session key), ABIA, ACCA or A3T prefix followed by 16 base32 characters, in any file. Not reported: the documented AWS example keys (ending in EXAMPLE), placeholder runs (AKIAXXXX..., AKIA0000...), a prefix embedded in a longer alphanumeric run, detector patterns and prefix lists, and test, fixture, vendored and generated files. The paired secret access key is VNX-SEC-003.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-001/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "aws", "credentials"],
}

_token := `(?:^|[^A-Za-z0-9])((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16})(?:[^A-Za-z0-9]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not _test_path(path)
	regex.match(`A(?:KIA|SIA|BIA|CCA|3T[A-Z0-9])[A-Z2-7]{16}`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`A(?:KIA|SIA|BIA|CCA|3T[A-Z0-9])[A-Z2-7]{16}`, line)
	some m in regex.find_all_string_submatch_n(_token, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.0)
	finding := {
		"rule_id": metadata.id,
		"message": "AWS access key ID found; deactivate and rotate it in IAM, then load credentials from the environment, an IAM role or a secrets manager",
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
