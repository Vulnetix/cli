# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_936

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-936",
	"name": "Cross-Site Request Forgery protection disabled (Laravel, Symfony, Kotlin Spring Security)",
	"description": "CWE-936 is the OWASP Top Ten 2013 category 'Cross-Site Request Forgery'. This rule reports CSRF protection switched off in the frameworks the other CSRF rules do not read (VNX-352 covers Django, Flask, Node.js and Rails; VNX-JAVA-010 Spring in Java; VNX-CS-005 ASP.NET). Reported: Laravel VerifyCsrfToken/ValidateCsrfToken middleware whose $except list contains '*' or '/*', Laravel 11 validateCsrfTokens(except: ['*']) and web(remove: [...CsrfToken]), routes registered withoutMiddleware(...CsrfToken), and a Kernel 'web' middleware group that omits the CSRF middleware (a commented-out entry counts as absent); Symfony csrf_protection: false or csrf_protection: { enabled: false } in YAML configuration, $framework->csrfProtection()->enabled(false) / csrfProtection(false) in PHP configuration, and a form type option 'csrf_protection' => false; Spring Security in Kotlin: csrf { disable() } (also as a csrf { block with disable() on its own line), .csrf { it.disable() }, .csrf().disable() (also with .disable() on the next line) and csrf(...::disable). Not reported: $except entries naming specific paths ('stripe/webhook', 'api/*'), other middleware's $except, csrf_protection: true, configuration under when@test or config/packages/test, test files, a Kotlin security configuration in the same file that is stateless (SessionCreationPolicy.STATELESS) and authenticates with bearer tokens (oauth2ResourceServer, jwt), other disable() calls (cors, frameOptions, httpBasic), csrf ignoringRequestMatchers for specific paths, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-936/",
	"languages": ["php", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [936],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["csrf", "cwe-936"],
}

_strip_dq(line) := regex.replace(line, `"([^"\\]|\\.)*"`, `""`)

_wild := `['"]/?\*['"]`

# ── Laravel ───────────────────────────────────────────────────────────────

_laravel_line := [
	`validateCsrfTokens\(\s*except\s*:\s*\[[^\]]*['"]/?\*['"]`,
	`->\s*(web|remove)\(\s*(remove\s*:\s*)?\[?[^)]*(Verify|Validate)CsrfToken\b`,
	`->\s*withoutMiddleware\(\s*\[?[^)]*(Verify|Validate)CsrfToken\b`,
]

_php_hits contains [path, i] if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	regex.match(`CsrfToken`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "CsrfToken")
	not helpers.is_comment_line(line)
	some re in _laravel_line
	regex.match(re, line)
	not regex.match(`\$this\s*->\s*withoutMiddleware`, line)
}

# $except = [... '*' ...] in the CSRF middleware.
_php_hits contains [path, k] if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	regex.match(`class\s+\w*(Verify|Validate)CsrfToken\w*\s+extends`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\$except\s*=\s*\[`, line)
	some k in numbers.range(i, min([count(lines) - 1, i + 30]))
	not _array_closed_before(lines, i, k)
	not helpers.is_comment_line(lines[k])
	regex.match(_wild, lines[k])
}

_array_closed_before(lines, i, k) if {
	k > i
	some x in numbers.range(i, k - 1)
	contains(lines[x], "]")
}

# A Kernel 'web' group without the CSRF middleware.
_php_hits contains [path, i] if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	contains(content, "middlewareGroups")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*['"]web['"]\s*=>\s*\[\s*$`, line)
	ends := [e |
		some e in numbers.range(i + 1, min([count(lines) - 1, i + 30]))
		regex.match(`^\s*\],?\s*$`, lines[e])
	]
	count(ends) > 0
	not _has_csrf(lines, i + 1, ends[0])
}

_has_csrf(lines, a, b) if {
	some x in numbers.range(a, b)
	contains(lines[x], "CsrfToken")
	not helpers.is_comment_line(lines[x])
}

# ── Symfony ───────────────────────────────────────────────────────────────

_php_hits contains [path, i] if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	regex.match(`csrf_protection|csrfProtection`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`csrf_protection|csrfProtection`, line)
	not helpers.is_comment_line(line)
	some re in [
		`(^\s*|[\[,(]\s*)['"]csrf_protection['"]\s*=>\s*false\b`,
		`->\s*csrfProtection\(\s*\)\s*->\s*enabled\(\s*false\s*\)`,
		`->\s*csrfProtection\(\s*false\s*\)`,
	]
	regex.match(re, line)
}

_yaml_hits contains [path, i] if {
	some path, content in input.file_contents
	regex.match(`\.ya?ml$`, path)
	not helpers.is_test_path(path)
	contains(content, "csrf_protection")
	regex.match(`(?m)^framework:|^\s+framework:`, content)
	lines := split(content, "\n")
	some i, line in lines
	_yaml_csrf_off(lines, i, line)
	not _under_test_env(lines, i)
}

_yaml_csrf_off(_, _, line) if regex.match(`^\s*csrf_protection:\s*(false|off|no)\s*(#.*)?$`, line)

_yaml_csrf_off(_, _, line) if regex.match(`^\s*csrf_protection:\s*\{\s*enabled:\s*(false|off|no)\s*\}\s*(#.*)?$`, line)

_yaml_csrf_off(lines, i, line) if {
	regex.match(`^\s*enabled:\s*(false|off|no)\s*(#.*)?$`, line)
	i > 0
	regex.match(`^\s*csrf_protection:\s*$`, lines[i - 1])
}

_under_test_env(lines, i) if {
	tops := [k | some k in numbers.range(0, i); regex.match(`^\S`, lines[k]); not startswith(lines[k], "#")]
	count(tops) > 0
	regex.match(`^when@test\s*:`, lines[tops[count(tops) - 1]])
}

# ── Kotlin Spring Security ────────────────────────────────────────────────

_kt_disable := [
	`^\s*csrf\s*\{\s*disable\(\s*\)\s*\}`,
	`\.csrf\s*\{\s*(it|\w+\s*->\s*\w+)\s*\.\s*disable\(\s*\)`,
	`\.csrf\(\s*\)\s*\.\s*disable\(\s*\)`,
	`\bcsrf\(\s*[\w.<>*, ]+::disable\s*\)`,
]

_kt_hits contains [path, i] if {
	some path, content in input.file_contents
	endswith(path, ".kt")
	not helpers.is_test_path(path)
	contains(content, "csrf")
	contains(content, "disable")
	not _stateless_token_auth(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`csrf|^\s*disable\(`, line)
	not helpers.is_comment_line(line)
	code := _strip_dq(line)
	_kt_off(lines, i, code)
}

# The Kotlin DSL block split over lines: csrf {\n    disable()\n}
_kt_off(lines, i, code) if {
	regex.match(`^\s*disable\(\s*\)\s*$`, code)
	opens := [k |
		some k in numbers.range(max([0, i - 3]), i - 1)
		regex.match(`^\s*csrf\s*\{\s*$`, lines[k])
	]
	count(opens) > 0
	o := max(opens)
	not _brace_between(lines, o, i)
}

_brace_between(lines, o, i) if {
	o + 1 <= i - 1
	some k in numbers.range(o + 1, i - 1)
	regex.match(`[{}]`, lines[k])
}

_kt_off(_, _, code) if {
	some re in _kt_disable
	regex.match(re, code)
}

_kt_off(lines, i, code) if {
	regex.match(`\.csrf\(\s*\)\s*$`, code)
	j := helpers.next_code_index(lines, i, 2)
	regex.match(`^\s*\.\s*disable\(\s*\)`, lines[j])
}

_stateless_token_auth(content) if {
	contains(content, "STATELESS")
	regex.match(`oauth2ResourceServer|\bjwt\b|(?i)bearer`, content)
}

_message := "Cross-Site Request Forgery protection is disabled: a page on another site can submit state-changing requests with the user's session cookie. Keep CSRF protection on and exempt only specific endpoints that authenticate without cookies (webhooks, token-authenticated APIs)"

findings contains finding if {
	some [path, i] in (_php_hits | _yaml_hits) | _kt_hits
	lines := split(input.file_contents[path], "\n")
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
