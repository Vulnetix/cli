package vulnetix.rules.vnx_sec_024

import rego.v1

metadata := {
	"id": "VNX-SEC-024",
	"name": "OAuth token stored in localStorage",
	"description": "An OAuth access token, refresh token, or ID token is stored in localStorage. localStorage is accessible to any JavaScript running on the page, making tokens vulnerable to XSS-based theft. Use httpOnly secure cookies or a backend-for-frontend pattern instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-024/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [922],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["oauth", "token-storage", "xss"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "localStorage.setItem")
	regex.match(`["'](access_token|id_token|refresh_token|token|auth_token)["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "OAuth/auth token stored in localStorage; localStorage is accessible to JavaScript and vulnerable to XSS theft — use httpOnly secure cookies instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
