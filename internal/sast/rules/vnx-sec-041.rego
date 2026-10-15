package vulnetix.rules.vnx_sec_041

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-041",
	"name": "Atlassian API token",
	"description": "Reports an Atlassian Cloud API token written into a file: the current ATATT3-prefixed token (about 190 characters of base64url with its checksum) anywhere in a line, and a legacy 24-character alphanumeric token quoted as the value of an Atlassian-, Jira- or Confluence-named token, key, secret or password field, or assigned unquoted to such a field as the whole of a dotenv, properties or shell line (JIRA_API_TOKEN=...). These tokens act as the issuing user on Jira, Confluence and Bitbucket Cloud. The snippet is redacted. Not reported: ATATT3 inside a longer identifier, truncated or placeholder tokens (xxxx, EXAMPLE, REPLACE), a legacy-shaped value with low entropy or no digits, tokens read from the environment, and test, fixture and vendored paths. Atlassian OAuth tokens and Connect shared secrets are VNX-SEC-788 and VNX-SEC-789.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-041/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "atlassian", "jira", "confluence", "credentials"],
}

_keywords := ["atatt3", "atlassian", "jira", "confluence"]

# Plain contains() over the whole file: a case-insensitive regex here costs
# more than the rest of the rule.
_gate_words := [
	"ATATT3", "atlassian", "Atlassian", "ATLASSIAN", "jira", "Jira", "JIRA",
	"confluence", "Confluence", "CONFLUENCE",
]

_gated(content) if {
	some w in _gate_words
	contains(content, w)
}

_current := `(?:^|[^A-Za-z0-9_-])(ATATT3[A-Za-z0-9_=-]{170,220})(?:[^A-Za-z0-9_=-]|$)`

_legacy := `(?i)(?:atlassian|jira|confluence)[a-z0-9_.-]{0,24}?(?:api[_-]?)?(?:token|key|secret|password|passwd|pass|pwd)["']?\s*(?::=|=>|[:=])\s*["']([A-Za-z0-9]{24})["']`

_token(line) := t if {
	contains(line, "ATATT3")
	m := regex.find_all_string_submatch_n(_current, line, 1)
	count(m) > 0
	t := m[0][1]
}

_token(line) := t if {
	m := regex.find_all_string_submatch_n(_legacy, line, 1)
	count(m) > 0
	t := m[0][1]
	regex.match(`[0-9]`, t)
	regex.match(`[A-Za-z]`, t)
	secrets.high_entropy(t, 3.5)
}

# The same field in a dotenv, properties or shell file, unquoted: the line is
# only the assignment, so the value must run to the end of the line.
_legacy_bare := `(?i)^\s*(?:export\s+)?[a-z0-9_.-]*(?:atlassian|jira|confluence)[a-z0-9_.-]{0,24}?(?:api[_-]?)?(?:token|key|secret|password|passwd|pass|pwd)\s*[:=]\s*([A-Za-z0-9]{24})\s*$`

_token(line) := t if {
	not regex.match(_legacy, line)
	not contains(line, "ATATT3")
	m := regex.find_all_string_submatch_n(_legacy_bare, line, 1)
	count(m) > 0
	t := m[0][1]
	regex.match(`[0-9]`, t)
	regex.match(`[A-Za-z]`, t)
	secrets.high_entropy(t, 3.5)
}

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
	_gated(content)
	lines := split(content, "\n")
	some i, line in lines
	secrets.has_keyword(line, _keywords)
	token := _token(line)
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": "Atlassian API token found; revoke the token in id.atlassian.com/manage-profile/security/api-tokens",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
