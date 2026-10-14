package vulnetix.rules.vnx_sec_046

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-046",
	"name": "Square access token",
	"description": "Reports a Square access token written into a file: a production or sandbox access token (EAAA followed by 56 to 64 base64url characters) and a legacy OAuth access token (sq0atp- followed by 22 to 43 characters), each standing alone rather than inside a longer base64 run. The token grants access to the seller's payments, customers and inventory. The snippet is redacted. Not reported: EAAA inside a longer base64 blob (images, certificates, wasm), placeholders (xxxx, EXAMPLE, REPLACE), low-entropy values, tokens read from the environment, and test, fixture and vendored paths. The generated VNX-SEC-328, VNX-SEC-330 and VNX-SEC-377 report the same token families.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-046/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "square", "payments", "credentials"],
}

_patterns := {
	"Square access token found; revoke the token in the Square developer dashboard": `(?:^|[^A-Za-z0-9+/_-])(EAAA[A-Za-z0-9_-]{56,64})(?:[^A-Za-z0-9+/=_-]|$)`,
	"Square OAuth access token found; revoke the token in the Square developer dashboard": `(?:^|[^A-Za-z0-9+/_-])(sq0atp-[A-Za-z0-9_-]{22,43})(?:[^A-Za-z0-9+/=_-]|$)`,
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	regex.match(`EAAA|sq0atp-`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`EAAA|sq0atp-`, line)
	some message, p in _patterns
	m := regex.find_all_string_submatch_n(p, line, 1)
	count(m) > 0
	token := m[0][1]
	regex.match(`[0-9]`, token)
	regex.match(`[a-z]`, token)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
