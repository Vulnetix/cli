package vulnetix.rules.vnx_kotlin_003

import rego.v1

metadata := {
	"id": "VNX-KOTLIN-003",
	"name": "Kotlin cookie missing HttpOnly flag",
	"description": "A Cookie is added to the HTTP response without calling setHttpOnly(true). Without the HttpOnly flag, client-side JavaScript can read the cookie, making session cookies vulnerable to XSS-based session hijacking.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-003/",
	"languages": ["kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [1004],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["cookie", "session", "xss", "kotlin"],
}

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "setHttpOnly(false)")
	finding := {
		"rule_id": metadata.id,
		"message": "Cookie HttpOnly flag explicitly set to false; set setHttpOnly(true) to prevent JavaScript from accessing the cookie and mitigate XSS session hijacking",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "addCookie(")
	not contains(line, "setHttpOnly")
	not contains(line, "httpOnly")
	finding := {
		"rule_id": metadata.id,
		"message": "Cookie added to response without calling setHttpOnly(true); always set HttpOnly on session and authentication cookies",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
