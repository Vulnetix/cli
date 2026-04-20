# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_613

import rego.v1

metadata := {
	"id": "VNX-613",
	"name": "Insufficient Session Expiration",
	"description": "Session tokens or cookies are configured with excessively long lifetimes or no expiration at all. Attackers who obtain a session token (via XSS, network sniffing, or log exfiltration) can reuse it indefinitely. Sessions should expire after a short period of inactivity and an absolute maximum lifetime.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-613/",
	"languages": ["python", "java", "node", "php", "ruby", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [613],
	"capec": ["CAPEC-60", "CAPEC-196"],
	"attack_technique": ["T1550"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["session", "expiration", "timeout", "cookie", "jwt", "cwe-613"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Django session age set to more than 30 days (2592000 seconds)
_django_long_age_patterns := {
	"SESSION_COOKIE_AGE = 86400 * 365",
	"SESSION_COOKIE_AGE = 86400 * 30",
	"SESSION_COOKIE_AGE = 86400 * 90",
	"SESSION_COOKIE_AGE = 86400 * 180",
	"SESSION_COOKIE_AGE = 31536000",
	"SESSION_COOKIE_AGE = 2592000",
}

# Java: session never expires
_java_no_expire_patterns := {
	"setMaxInactiveInterval(-1)",
	"setMaxInactiveInterval(0)",
	"setMaxInactiveInterval(-1L)",
}

# JWT issued without expiry
_jwt_no_exp_patterns := {
	"jwt.sign(",
	"jwt.encode(",
	"JWT.create()",
	"Jwts.builder()",
}

# PHP: session cookie lifetime set to 0 years or very long
_php_long_session_patterns := {
	"session.cookie_lifetime",
	"ini_set('session.gc_maxlifetime'",
	"ini_set(\"session.gc_maxlifetime\"",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _django_long_age_patterns
	contains(line, p)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Django SESSION_COOKIE_AGE pattern '%s' sets an excessively long session lifetime; use a short expiry (e.g. 3600 seconds) to limit the window of session token reuse", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _java_no_expire_patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java session '%s' sets an infinite or zero inactivity timeout; configure a finite timeout (e.g. 1800 seconds) to invalidate idle sessions", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# JWT sign/encode calls without 'exp' or 'expiresIn' on the same line
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _jwt_no_exp_patterns
	contains(line, p)
	not contains(line, "expiresIn")
	not contains(line, "\"exp\"")
	not contains(line, "'exp'")
	not contains(line, ".withExpiresAt(")
	not contains(line, ".setExpiration(")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("JWT operation '%s' does not appear to set an expiry claim (exp/expiresIn); always issue JWTs with a short-lived expiry to prevent indefinite token reuse", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _php_long_session_patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP session lifetime configuration '%s' detected; verify this is set to a short value (e.g. 1800) and that session.gc_maxlifetime is not set excessively high", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
