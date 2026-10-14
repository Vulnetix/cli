package vulnetix.rules.vnx_sec_031

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-031",
	"name": "Mailgun API key hardcoded",
	"description": "Reports a Mailgun private API key: the legacy key- form (key- and 32 lowercase letters or digits, delimited so pubkey- validation keys and longer words do not match) in a file that mentions Mailgun or an MG_API_KEY-style name, and the current form (32 hex, dash, 8 hex, dash, 8 hex) when Mailgun is named within three lines of it. Public validation keys, key- values in files with no Mailgun context, placeholders and low-entropy values, environment references, and test and fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-031/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secret", "mailgun", "email", "credentials"],
}

_legacy_re := `(?:^|[^A-Za-z0-9_-])(key-[0-9a-z]{32})(?:[^A-Za-z0-9_-]|$)`

_current_re := `(?:^|[^A-Za-z0-9_-])([0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})(?:[^A-Za-z0-9_-]|$)`

_ctx_re := `(?i)(mailgun|\bmg[_.-]?(api[_.-]?)?key\b)`

# Cheap whole-file prefilter for _ctx_re ("Mailgun", "mailgun", "MAILGUN",
# MG_API_KEY, mg_key ...).
_file_words := ["ailgun", "AILGUN", "MG_", "mg_", "Mg_", "mgKey", "mgApiKey", "MG-", "mg-"]

_file_ctx(content) if {
	some w in _file_words
	contains(content, w)
}

_near_ctx(lines, i) if {
	some j in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	regex.match(_ctx_re, lines[j])
}

_hit(lines, i, line) if {
	contains(line, "key-")
	m := regex.find_all_string_submatch_n(_legacy_re, line, -1)
	some hit in m
	token := hit[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(substring(token, 4, -1), 3.3)
}

_hit(lines, i, line) if {
	m := regex.find_all_string_submatch_n(_current_re, line, -1)
	some hit in m
	token := hit[1]
	_near_ctx(lines, i)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.0)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	_file_ctx(content)
	regex.match(`(key-[0-9a-z]{32}|[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})`, content)
	lines := split(content, "\n")
	some i, line in lines
	_hit(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Mailgun API key detected; revoke at app.mailgun.com/settings/api_security and store in environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
