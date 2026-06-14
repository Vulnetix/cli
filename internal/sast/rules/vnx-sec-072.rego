package vulnetix.rules.vnx_sec_072

import rego.v1

metadata := {
	"id": "VNX-SEC-072",
	"name": "Generic high-entropy API key / secret",
	"description": "A high-entropy string was assigned to a variable whose name contains 'api_key', 'apikey', 'secret', 'token', 'password', 'passwd', 'credential', or 'auth'. The string is long, mixes case, digits, and punctuation, which is consistent with a hard-coded credential.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-072/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "generic", "high-entropy", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".test")
_skip(path) if endswith(path, "_test.go")
_skip(path) if endswith(path, ".spec.ts")
_skip(path) if endswith(path, ".spec.js")
_skip(path) if endswith(path, ".md")
_skip(path) if endswith(path, ".svg")
_skip(path) if endswith(path, ".html")

_keyword_pattern := `(?i)(api_?key|apikey|secret|token|password|passwd|credential|creds|auth)`

# Match high-entropy (40+ chars, mix of case/digit/symbol) string assigned to a variable
# with a credential-suggesting name.
_value_pattern := `(?i)(api_?key|apikey|secret|token|password|passwd|credential|creds|auth)[a-z_0-9]*\s*[:=]\s*['"]?[A-Za-z0-9+/=_\-]{32,}['"]?`

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(_value_pattern, line)
	not contains(lower(line), "example")
	not contains(lower(line), "placeholder")
	not contains(lower(line), "your-")
	not contains(lower(line), "<your")
	not contains(lower(line), "xxxxx")
	not contains(lower(line), "redacted")
	finding := {
		"rule_id": metadata.id,
		"message": "High-entropy credential-like string assigned to a variable; verify it is not a real secret",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
