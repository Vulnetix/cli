package vulnetix.rules.vnx_sec_037

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-037",
	"name": "HashiCorp Vault token",
	"description": "Reports a HashiCorp Vault token: a standalone hvs. service token (24 or more base62 characters, so root and namespaced tokens are included), an hvb. batch token (138 to 300 characters), or a legacy s. service token (24 characters) only where it is assigned to a Vault token setting (VAULT_TOKEN=, vault_token:, X-Vault-Token:, token = inside a vault block). A bare s.-prefixed word, placeholders and test or fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-037/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "vault", "hashicorp", "credentials"],
}

_modern := `\b(hvs\.[A-Za-z0-9_-]{24,}|hvb\.[A-Za-z0-9_-]{138,300})(?:[^A-Za-z0-9_-]|$)`

# Legacy tokens ("s." + 24 base62) are only distinguishable by their setting.
_legacy := `(?i)(?:vault[a-z0-9_.-]*token|x-vault-token)["']?\s*(?::=|=>|[:=])\s*["']?(s\.[A-Za-z0-9]{24})(?:[^A-Za-z0-9_-]|$)`

_kind(tok) := "service" if startswith(tok, "hvs.")
_kind(tok) := "batch" if startswith(tok, "hvb.")
_kind(tok) := "legacy service" if startswith(tok, "s.")

_hit(line) := m[0][1] if {
	regex.match(`hv[sb]\.`, line)
	m := regex.find_all_string_submatch_n(_modern, line, 1)
	count(m) > 0
}

_hit(line) := m[0][1] if {
	not regex.match(`hv[sb]\.`, line)
	contains(lower(line), "vault")
	m := regex.find_all_string_submatch_n(_legacy, line, 1)
	count(m) > 0
}

_gate(content) if contains(content, "hvs.")
_gate(content) if contains(content, "hvb.")
_gate(content) if contains(content, "vault")
_gate(content) if contains(content, "Vault")
_gate(content) if contains(content, "VAULT")

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	tok := _hit(line)
	not secrets.is_example_token(tok)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("HashiCorp Vault %s token found; revoke it with 'vault token revoke' and rotate the secrets its policy could read", [_kind(tok)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
