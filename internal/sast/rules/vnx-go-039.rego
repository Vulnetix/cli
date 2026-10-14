package vulnetix.rules.vnx_go_039

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-039",
	"name": "Missing rate limiting on login endpoint",
	"description": "An HTTP handler for login or authentication is declared and nothing in the project's production Go code rate-limits requests (a limiter, throttle or rate-limit middleware). Login endpoints without rate limiting are vulnerable to brute force attacks. The handler is recognised from its declaration (a function or handler method whose name is the login path, Login/handleLogin/SignIn/Authenticate, and that takes a response writer or framework context, parameters possibly wrapped onto the next line) or from a login route registered with an inline handler (r.POST(\"/login\", func(c *gin.Context) {...})). Not reported: a client method or helper named Login that is not an HTTP handler, a parser or CLI command, test files, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-039/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [307],
	"capec": ["CAPEC-49"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["rate-limiting", "brute-force", "login"],
}

_is_go(path) if endswith(path, ".go")

# A function that handles an HTTP request: it takes a response writer or a
# framework context.
_handler_params := `(http\.ResponseWriter|http\.Handler|\*gin\.Context|echo\.Context|\*fiber\.Ctx|iris\.Context|\*fasthttp\.RequestCtx|\*buffalo\.Context)`

# The function NAME says it is the login path. The name is read from the
# declaration, never from a receiver type or a parameter.
_login_name := `^(?i:(handle|serve|do|post|api)?_?(login|log_in|signin|sign_in|authenticate))\w*$`

_func_name(line) := name if {
	m := regex.find_all_string_submatch_n(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(`, line, 1)
	count(m) > 0
	name := m[0][1]
}

# Rate limiting anywhere in production Go code: a limiter configured in
# middleware protects a login handler in another file.
_project_rate_limits if {
	some p, content in input.file_contents
	_is_go(p)
	not helpers.is_test_path(p)
	regex.match(`(?i)(ratelimit|rate_limit|ratelimiter|rate\.NewLimiter|limiter|throttle|tollbooth|httprate)`, content)
}

# A declared handler whose name is the login path. Its parameters may wrap
# onto the next line.
_login_handler(lines, i, line) if {
	name := _func_name(line)
	regex.match(_login_name, name)
	params := concat(" ", [line, _next(lines, i)])
	regex.match(_handler_params, params)
}

# A login route registered with an inline handler: r.POST("/login", func(c *gin.Context) {.
_login_handler(_, _, line) if {
	regex.match(`\.(?i:post|handlefunc|handle|any|match)\(\s*"[^"]*/(?i:login|log-in|signin|sign-in|sign_in|authenticate)/?"\s*,\s*func\s*\(`, line)
	regex.match(_handler_params, line)
}

findings contains finding if {
	not _project_rate_limits
	some path, content in input.file_contents
	_is_go(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)log_?in|sign_?in|authenticate`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^func\s|(?i:login|signin|sign-in|sign_in|authenticate)"`, line)
	_login_handler(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Login handler without apparent rate limiting anywhere in the project; add rate limiting to prevent brute force attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_next(lines, i) := lines[i + 1] if i + 1 < count(lines)

_next(lines, i) := "" if i + 1 >= count(lines)
