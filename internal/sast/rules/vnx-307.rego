# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_307

import rego.v1

metadata := {
	"id": "VNX-307",
	"name": "Improper restriction of excessive authentication attempts",
	"description": "Login or authentication endpoints are defined without rate limiting decorators, middleware, or account lockout logic. Without these controls, an attacker can perform brute-force or credential-stuffing attacks without being blocked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-307/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [307],
	"capec": ["CAPEC-49", "CAPEC-112"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["auth", "brute-force", "rate-limit", "lockout"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

# Flag login/auth route definitions that lack rate limiting annotations near them.
# This is a heuristic: flag route/function definitions that mention login/auth.
_login_route_patterns := {
	`@app.route("/login"`,
	`@app.route('/login'`,
	`router.post("/login"`,
	`router.post('/login'`,
	`app.post("/login"`,
	`app.post('/login'`,
	`router.post("/auth"`,
	`router.post('/auth'`,
	`app.post("/auth"`,
	`app.post('/auth'`,
	`path("/login"`,
	`path('/login'`,
	`http.HandleFunc("/login"`,
	`http.HandleFunc('/login'`,
	`r.POST("/login"`,
	`r.POST('/login'`,
}

_missing_rate_limit_context_patterns := {
	"@login_required",
	"@ratelimit",
	"@rate_limit",
	"rateLimit(",
	"rateLimiter",
	"throttle(",
	"limiter.Allow",
	"redis.Incr",
	"account_locked",
	"lockout",
	"max_attempts",
	"maxAttempts",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	content := input.file_contents[path]
	lines := split(content, "\n")
	some i, line in lines
	some route_pattern in _login_route_patterns
	contains(line, route_pattern)
	# Heuristic: check that none of the rate limit indicators appear anywhere in this file
	not any_rate_limit_present(content)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Login/auth route defined without apparent rate limiting (pattern: %s); add rate limiting middleware or account lockout to prevent brute-force attacks", [route_pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

any_rate_limit_present(content) if {
	some indicator in _missing_rate_limit_context_patterns
	contains(content, indicator)
}
