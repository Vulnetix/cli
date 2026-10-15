package vulnetix.rules.vnx_sec_048

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-048",
	"name": "OpenAI project / service / admin key",
	"description": "Reports an OpenAI project, service-account or admin key written into a file: sk-proj-, sk-svcacct- or sk-admin- followed by at least 40 base64url characters, standing alone rather than inside a longer identifier. These keys bill the organisation and can read its files, assistants and fine-tunes. The snippet is redacted. Not reported: truncated or elided keys (sk-proj-..., sk-proj-abc), placeholders (xxxx, your-key, EXAMPLE, REPLACE), low-entropy values, keys read from the environment, and test, fixture and vendored paths. Classic sk-...T3BlbkFJ keys are VNX-SEC-251; VNX-SEC-018 and VNX-LLM-003 also report project keys.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-048/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "openai", "ai", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})`

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
	regex.match(`sk-(?:proj|svcacct|admin)-`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "sk-")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	regex.match(`[0-9]`, token)
	regex.match(`[A-Z]`, token)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "OpenAI project/service/admin key found; revoke the key in the OpenAI dashboard",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
