package vulnetix.rules.vnx_sec_004

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-004",
	"name": "GitHub or GitLab token",
	"description": "Reports a hard-coded GitHub or GitLab token in any file: a GitHub classic personal access, OAuth, user-to-server, installation or refresh token (ghp_, gho_, ghu_, ghs_, ghr_ followed by 36 characters), a GitHub fine-grained token (github_pat_…), and a GitLab personal/project access token (glpat- followed by 20 or more characters, including the newer dotted format), standalone or inside a clone URL or header. Not reported: placeholder runs (ghp_xxxx…, glpat-XXXX…), truncated tokens, prefix lists and prefix checks, environment and CI-secret references, and test, fixture, vendored and generated files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-004/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "github", "gitlab", "tokens"],
}

_patterns := [
	["GitHub", `(?:^|[^A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36})(?:[^A-Za-z0-9_]|$)`],
	["GitHub", `(?:^|[^A-Za-z0-9_])(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})(?:[^A-Za-z0-9_]|$)`],
	["GitLab", `(?:^|[^A-Za-z0-9_-])(glpat-[A-Za-z0-9_-]{20,})`],
]

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_|glpat-[A-Za-z0-9_-]{20}`, content)
	not secrets.skip_path(path)
	not _test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`gh[pousr]_|github_pat_|glpat-`, line)
	some p in _patterns
	some m in regex.find_all_string_submatch_n(p[1], line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s access token found; revoke it in the %s token settings and load it from the environment or a secrets manager", [p[0], p[0]]),
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
