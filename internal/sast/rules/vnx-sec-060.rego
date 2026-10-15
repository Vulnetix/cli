package vulnetix.rules.vnx_sec_060

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-060",
	"name": "Airtable personal access token",
	"description": "Reports an Airtable credential written into a file: a personal access token (pat + 14 alphanumerics + . + 64 hex) anywhere, and a legacy API key (key + 14 alphanumerics) only when Airtable (airtable, AIRTABLE_API_KEY, Airrecord) is named on that line or up to three lines above it, since key followed by letters is an ordinary identifier. Each must stand alone rather than inside a longer identifier. Airtable tokens read and write the bases they are scoped to. The snippet is redacted. Not reported: placeholder or low-entropy bodies (XXXX, YOUR_KEY_HERE), key-prefixed names on lines without Airtable context, tokens read from the environment, and test, fixture and vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-060/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "airtable", "credentials"],
}

_pat := `(?:^|[^A-Za-z0-9_])(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})(?:[^A-Za-z0-9_]|$)`

_legacy := `(?:^|[^A-Za-z0-9_])(key[A-Za-z0-9]{14})(?:[^A-Za-z0-9_]|$)`

_tokens(lines, i) := _pat_tokens(lines[i]) | _legacy_tokens(lines, i)

default _pat_tokens(_) := set()

_pat_tokens(line) := {[m[1], 3.5] | some m in regex.find_all_string_submatch_n(_pat, line, -1)} if contains(line, "pat")

default _legacy_tokens(_, _) := set()

_legacy_tokens(lines, i) := {[m[1], 3.0] |
	some m in regex.find_all_string_submatch_n(_legacy, lines[i], -1)
	regex.match(`[0-9]`, m[1])
	regex.match(`[A-Za-z].*[A-Za-z]`, substring(m[1], 3, -1))
	not regex.match(`(?i)your|here`, m[1])
} if {
	contains(lines[i], "key")
	_airtable_context(lines, i)
}

# Airtable named on the key line or up to three lines above it, as in a
# multi-line `new Airtable({ apiKey: "key..." })` call.
# A comment above the key does not count: it may say the opposite.
_airtable_context(lines, i) if _names_airtable(lines[i])

_airtable_context(lines, i) if {
	some j in numbers.range(max([0, i - 3]), i - 1)
	not helpers.is_comment_line(lines[j])
	_names_airtable(lines[j])
}

# Literal checks (Airtable, airtable, AIRTABLE, Airrecord) instead of a
# case-insensitive regex over every line.
_names_airtable(s) if contains(s, "irtable")

_names_airtable(s) if contains(s, "IRTABLE")

_names_airtable(s) if contains(s, "irrecord")

# Whole-file gate: a PAT-shaped run, or a file naming Airtable for legacy keys.
_candidate(content) if {
	contains(content, "pat")
	regex.match(`pat[A-Za-z0-9]{14}\.[a-f0-9]`, content)
}

_candidate(content) if {
	_names_airtable(content)
	regex.match(`key[A-Za-z0-9]{14}`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	_candidate(content)
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	some t in _tokens(lines, i)
	not secrets.is_example_token(t[0])
	secrets.high_entropy(t[0], t[1])
	finding := {
		"rule_id": metadata.id,
		"message": "Airtable access token found; revoke it in the Airtable developer hub and load it from a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
