package vulnetix.rules.vnx_sec_076

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-076",
	"name": "Telegram bot API token",
	"description": "Reports a Telegram Bot API token as a whole token in any file: the bot's numeric id (8 to 10 digits), a colon, and the 35-character secret that begins AA, whether quoted, assigned, in an api.telegram.org/bot<token>/ URL or in a .env file. Not reported: a bot id alone, a placeholder body (AAxxxx..., AAAA...), a low-entropy body, environment references, and test, fixture, vendored and generated files. The generated rule VNX-SEC-728 reports the same token.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-076/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "telegram", "credentials"],
}

# bot id : AA + 33 more characters. The body is base64url, so mixed case,
# digits, "_" and "-". The original rule allowed only lower case after the
# "A" and could never match a real token.
# "bot" may run straight into the id in an API URL (/bot<id>:<secret>/).
_pattern := `(?:^|[^0-9A-Za-z]|bot)([0-9]{8,10}:AA[A-Za-z0-9_-]{33})(?:[^A-Za-z0-9_-]|$)`

findings contains finding if {
	some path, content in input.file_contents
	contains(content, ":AA")
	regex.match(`[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ":AA")
	some m in regex.find_all_string_submatch_n(_pattern, line, -1)
	token := m[1]
	body := substring(token, indexof(token, ":") + 1, -1)
	not secrets.is_example_token(body)
	secrets.high_entropy(body, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Telegram bot API token found; revoke it via @BotFather (/revoke) and load the replacement from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
