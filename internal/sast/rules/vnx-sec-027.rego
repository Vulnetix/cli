package vulnetix.rules.vnx_sec_027

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-027",
	"name": "Hugging Face API token hardcoded",
	"description": "Reports a Hugging Face user access token: hf_ followed by 34 to 40 letters or digits, delimited on both sides (so a longer snake_case identifier is not one), in any file including notebooks and .env files. Placeholders and low-entropy values, CamelCase and lowerCamelCase identifiers that merely start with hf_ (hf_TokenizerFastLoader..., hf_parseModelCard...), regular expressions for the token, environment lookups, and test and fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-027/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secret", "huggingface", "ai", "credentials"],
}

_token_re := `(?:^|[^A-Za-z0-9_])(hf_[A-Za-z0-9]{34,40})(?:[^A-Za-z0-9_]|$)`

# An identifier spelled as CamelCase words ("hf_TokenizerFastLoader...") is
# code, not a random token: a random 34-character string almost never avoids
# two capitals in a row.
_identifier(body) if regex.match(`^(?:[A-Z][a-z0-9]+)+$`, body)

# lowerCamelCase (hf_parseModelCardFrontMatter...) is code as well.
_identifier(body) if regex.match(`^[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+)+$`, body)

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	contains(content, "hf_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "hf_")
	m := regex.find_all_string_submatch_n(_token_re, line, -1)
	some hit in m
	token := hit[1]
	body := substring(token, 3, -1)
	not _identifier(body)
	not secrets.is_example_token(token)
	secrets.high_entropy(body, 4.0)
	finding := {
		"rule_id": metadata.id,
		"message": "Hugging Face API token detected; revoke at huggingface.co/settings/tokens and store in environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
