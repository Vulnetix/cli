package vulnetix.rules.vnx_sec_045

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-045",
	"name": "Discord bot token",
	"description": "Reports a Discord bot token written into a file: three dot-separated base64url segments whose first segment is the base64 encoding of a numeric Discord snowflake id (17 to 20 digits, which fixes the character at every position), a 6-character timestamp and a 27- or 38-character HMAC. The token grants full control of the bot account. The snippet is redacted. Not reported: dotted strings whose first segment cannot decode to digits (JWTs, hashes, other base64), segments inside a longer token, placeholders (xxxx, EXAMPLE), and test, fixture and vendored paths. Discord webhook URLs and client secrets are VNX-SEC-417, VNX-SEC-726 and VNX-SEC-418.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-045/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "discord", "credentials"],
}

# Base64 of ASCII digits: every 4-character group is [MNO][DTjz][AEIMQUYcgk][w-z0-5];
# a trailing 1-byte remainder is [MNO][AQgw], a 2-byte one [MNO][DTjz][AEIMQUYcgk].
_id := `(?:[MNO][DTjz][AEIMQUYcgk][w-z0-5]){5,6}(?:[MNO][DTjz][AEIMQUYcgk]|[MNO][AQgw])?`

_token_re := concat("", [`(`, _id, `\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38})`])

_pattern := concat("", [`(?:^|[^A-Za-z0-9_.-])`, _token_re, `(?:[^A-Za-z0-9_.-]|$)`])

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	regex.match(_token_re, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": "Discord bot token found; regenerate the token in the Discord developer portal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
