package vulnetix.rules.vnx_sec_077

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-077",
	"name": "Mapbox access token",
	"description": "Reports a Mapbox public access token as a whole token in any file: pk. followed by its base64url payload (eyJ...), a dot and a 22-character signature, quoted, assigned (mapboxgl.accessToken = ...), in a tile or API URL (?access_token=pk...) or in a .env file. Public tokens are designed to ship in browser code, so a finding asks you to confirm the token is URL- and scope-restricted, and to rotate it if it is not. Not reported: secret (sk.) tokens, which VNX-SEC-904 reports, placeholder or low-entropy bodies, environment references, and test, fixture, Jest __mocks__, vendored, minified and generated files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-077/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "mapbox", "credentials"],
}

# pk.<base64url JSON claims, always starting eyJ>.<22-char signature>. The
# original rule allowed only lower-case letters and digits, so no real token
# (the payload is mixed case) could match.
_pattern := `(?:^|[^A-Za-z0-9_.-])(pk\.eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{22})(?:[^A-Za-z0-9_-]|$)`

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "pk.eyJ")
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not contains(concat("", ["/", path]), "/__mocks__/")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "pk.eyJ")
	some m in regex.find_all_string_submatch_n(_pattern, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 4)
	finding := {
		"rule_id": metadata.id,
		"message": "Mapbox access token found; restrict it to your URLs and scopes in the Mapbox account, or rotate it and load it from configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
