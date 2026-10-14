package vulnetix.rules.vnx_sec_034

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-034",
	"name": "Alibaba Cloud access key",
	"description": "Reports an Alibaba Cloud RAM AccessKey ID: a standalone token of LTAI followed by 12 or 20 letters and digits (the 16- and 24-character ID formats), in either case. A token made of letters only in a single case, placeholder values and test or fixture paths are not reported; the AccessKey secret is covered by VNX-SEC-161 and STS keys by VNX-SEC-145.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-034/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "alibaba", "credentials"],
}

_pattern := `\b(LTAI(?:[A-Za-z0-9]{20}|[A-Za-z0-9]{12}))\b`

# A real ID mixes digits and letters; "LTAIGOODBYEWORLDS" is a word.
_wordlike(tok) if regex.match(`^LTAI(?:[A-Z]+|[a-z]+)$`, tok)

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "LTAI")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "LTAI")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not _wordlike(token)
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": "Alibaba Cloud AccessKey ID found; disable and rotate the AccessKey pair in RAM and load credentials from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
