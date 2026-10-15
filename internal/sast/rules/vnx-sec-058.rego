package vulnetix.rules.vnx_sec_058

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-058",
	"name": "Notion API token",
	"description": "Reports a Notion integration token written into a file: the current format ntn_ + 11 digits + 35 alphanumerics, and the legacy internal-integration format secret_ + 43 alphanumerics when the file mentions Notion (secret_ alone is too common a prefix to report without it). Each token must stand alone rather than inside a longer identifier. Notion tokens read and write every page and database shared with the integration. The snippet is redacted. Not reported: bare prefixes in a prefix check, placeholder or low-entropy bodies (xxxx, 0000, YOUR_TOKEN), tokens read from the environment, and test, fixture and vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-058/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "notion", "credentials"],
}

_ntn := `(?:^|[^A-Za-z0-9_])(ntn_[0-9]{11}[A-Za-z0-9]{35})(?:[^A-Za-z0-9_]|$)`

_legacy := `(?:^|[^A-Za-z0-9_])(secret_[A-Za-z0-9]{43})(?:[^A-Za-z0-9_]|$)`

_tokens(line, notion) := _ntn_tokens(line) | _legacy_tokens(line, notion)

default _ntn_tokens(_) := set()

_ntn_tokens(line) := {m[1] | some m in regex.find_all_string_submatch_n(_ntn, line, -1)} if contains(line, "ntn_")

default _legacy_tokens(_, _) := set()

_legacy_tokens(line, true) := {m[1] |
	some m in regex.find_all_string_submatch_n(_legacy, line, -1)
	regex.match(`[0-9]`, m[1])
} if contains(line, "secret_")

# Literal checks for Notion, notion and NOTION, without lowering the file.
default _names_notion(_) := false

_names_notion(s) if contains(s, "notion")

_names_notion(s) if contains(s, "Notion")

_names_notion(s) if contains(s, "NOTION")

# A new-format token anywhere, or a legacy secret_ token in a file naming Notion.
_candidate(content, _) if contains(content, "ntn_")

_candidate(content, true) if contains(content, "secret_")

findings contains finding if {
	some path, content in input.file_contents
	notion := _names_notion(content)
	_candidate(content, notion)
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	some token in _tokens(line, notion)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Notion API token found; revoke the integration's secret in Notion (Settings > Connections) and load it from a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
