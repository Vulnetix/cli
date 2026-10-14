package vulnetix.rules.vnx_sec_047

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-047",
	"name": "Shopify access token",
	"description": "Reports a Shopify token written into a file: an Admin API access token (shpat_), a custom app access token (shpca_), a private app password (shppa_) or a shared secret (shpss_), each followed by exactly 32 hexadecimal characters and standing alone. These grant API access to the store's products, customers and orders. The snippet is redacted. Not reported: the prefix inside a longer identifier, a body longer or shorter than 32 hex characters, placeholders (shpat_xxxx..., shpat_000..., EXAMPLE), low-entropy values, tokens read from the environment, and test, fixture and vendored paths. Context-named Shopify secrets without a prefix are VNX-SEC-882 and VNX-SEC-883.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-047/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "shopify", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_])(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "shp")
	regex.match(`shp(?:at|ca|pa|ss)_`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "shp")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	secrets.high_entropy(substring(token, 6, -1), 3.0)
	finding := {
		"rule_id": metadata.id,
		"message": "Shopify access token found; revoke the token in the Shopify admin",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
