package vulnetix.rules.vnx_node_025

import rego.v1

metadata := {
	"id": "VNX-NODE-025",
	"name": "Insecure express-session or cookie-session configuration",
	"description": "express-session or cookie-session is configured without the secure:true cookie flag. Without this flag, session cookies are transmitted over plain HTTP, allowing network attackers to steal session tokens. Set cookie.secure:true (combined with HTTPS in production) and cookie.httpOnly:true to prevent client-side JavaScript from reading the cookie.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-025/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [614],
	"capec": ["CAPEC-60"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["session", "cookie", "secure-flag", "express", "node"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "secure:")
	contains(line, "false")
	regex.match(`(express-session|cookie-session|cookieSession|session\()`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Session cookie has secure:false; set secure:true to ensure the cookie is only sent over HTTPS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "httpOnly:")
	contains(line, "false")
	regex.match(`(express-session|cookie-session|cookieSession|session\()`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Session cookie has httpOnly:false; set httpOnly:true to prevent client-side JavaScript from accessing the session cookie",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "resave:")
	contains(line, "true")
	regex.match(`(express-session|session)\s*\(`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "express-session configured with resave:true; this causes unnecessary session saves on every request — set resave:false to reduce session store load",
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}
