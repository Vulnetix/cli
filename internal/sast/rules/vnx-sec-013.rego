package vulnetix.rules.vnx_sec_013

import rego.v1

metadata := {
	"id": "VNX-SEC-013",
	"name": "Insecure cookie configuration",
	"description": "Cookies set without HttpOnly, Secure, or SameSite flags are vulnerable to theft via XSS, transmission over cleartext HTTP, or cross-site request forgery.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-013/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [614, 1004],
	"capec": ["CAPEC-31"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cookies", "session", "web-security"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_insecure_cookie_indicators := {
	"httpOnly: false",
	"HttpOnly: false",
	"httponly=False",
	"secure: false",
	"Secure: false",
	"secure=False",
	"HttpOnly = false",
	"Secure = false",
	"SESSION_COOKIE_SECURE = False",
	"SESSION_COOKIE_HTTPONLY = False",
	"CSRF_COOKIE_SECURE = False",
	"cookie_secure = false",
	"cookie_httponly = false",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _insecure_cookie_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "Cookie set without security flags; enable HttpOnly, Secure, and SameSite attributes",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
