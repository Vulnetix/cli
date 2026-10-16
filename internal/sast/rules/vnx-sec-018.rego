package vulnetix.rules.vnx_sec_018

import rego.v1

import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-018",
	"name": "AI provider API key",
	"description": "Reports an AI provider API key written into a file: an Anthropic key (sk-ant-api03-, sk-ant-admin01- or another sk-ant-<kind><nn>- prefix with a 40+ character body), an OpenAI project, service-account or admin key (sk-proj-, sk-svcacct-, sk-admin- with a 40+ character body), or a Hugging Face user access token (hf_ followed by 34+ letters and digits in both letter cases). The token must stand alone (not the tail of a longer identifier), must not be a placeholder (xxxx, your-key, EXAMPLE) and must have the entropy of a real key; the snippet is redacted. Not reported: keys read from the environment or a secrets manager, truncated or documentation keys shorter than the real format, identifiers such as hf_ followed only by lowercase letters, and test, fixture, vendored and generated paths. Overlaps VNX-LLM-003 (LLM-focused view) and the generated provider rules VNX-SEC-027/049/251/252/285/298/299.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-018/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "ai", "anthropic", "openai", "huggingface"],
}

_patterns := [
	{"re": `(?:^|[^\w-])(sk-ant-[a-z]+\d{2}-[A-Za-z0-9_-]{40,})`, "who": "Anthropic API key"},
	{"re": `(?:^|[^\w-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})`, "who": "OpenAI API key"},
	{"re": `(?:^|[^\w-])(hf_[A-Za-z0-9]{34,})(?:[^\w-]|$)`, "who": "Hugging Face access token"},
]

_whos(line) := {p.who |
	some p in _patterns
	some m in regex.find_all_string_submatch_n(p.re, line, -1)
	tok := m[1]
	not secrets.is_example_token(tok)
	secrets.high_entropy(tok, 3.5)
	_mixed_case(tok)
}

# Real keys are random over both letter cases; a run of lowercase letters
# after hf_ is an identifier (hf_modelrepositoryidentifier...), not a token.
_mixed_case(tok) if {
	regex.match(`[A-Z]`, substring(tok, 3, -1))
	regex.match(`[a-z]`, substring(tok, 3, -1))
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	_gate(content)

	lines := split(content, "\n")
	some i, line in lines
	regex.match(`sk-ant-|sk-proj-|sk-svcacct-|sk-admin-|hf_`, line)
	some who in _whos(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s found; revoke and rotate it at the provider, then load it from the environment or a secrets manager", [who]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

_gate(content) if {
	some s in ["sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-"]
	contains(content, s)
}

_gate(content) if contains(content, "hf_")
