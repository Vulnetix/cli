package vulnetix.rules.vnx_java_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-010",
	"name": "Spring CSRF protection disabled",
	"description": "Spring Security's CSRF protection is switched off for a browser-facing configuration: http.csrf().disable() (also with .disable() on the next line), .csrf(c -> c.disable()), .csrf(AbstractHttpConfigurer::disable) and other ::disable method references including WebFlux's ServerHttpSecurity.CsrfSpec::disable, CSRF ignored for every path (ignoringAntMatchers/ignoringRequestMatchers(\"/**\")), and <csrf disabled=\"true\"/> in a Spring Security XML namespace configuration. Not reported: CSRF ignored for specific paths (a webhook, an actuator endpoint), a configuration in the same file that is stateless (SessionCreationPolicy.STATELESS) and authenticates with bearer tokens (oauth2ResourceServer, JWT or bearer-token filters), where no ambient credential exists to forge, other .disable() calls (cors, frameOptions), test configurations, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-010/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [352],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1189"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["csrf", "spring", "web-security"],
}

_msg := "CSRF protection disabled in Spring Security; keep it enabled for any endpoint a browser reaches with a session cookie or other ambient credential, and exempt only specific token-authenticated paths"

_blank(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_disable_re := `\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|\.csrf\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)|\.csrf\s*\(\s*[\w.]+\s*::\s*disable\s*\)`

_ignore_all_re := `\.ignoring(?:Ant|Request|Mvc)?Matchers\s*\(\s*"/\*\*?"\s*\)`

# A stateless API authenticated by bearer tokens carries no ambient
# credential a forged request could ride on.
_token_api(content) if {
	contains(content, "SessionCreationPolicy.STATELESS")
	regex.match(`oauth2ResourceServer|\bJwt\w*Filter\b|\bjwt\s*\(|BearerToken\w*`, content)
}

# The statement starting at line i joined with the next two code lines, so
# that `.csrf()` / `.disable()` and `csrf(c ->` / `c.disable())` read as one.
_joined(lines, i) := concat(" ", [_blank(lines[k]) |
	some k in numbers.range(i, min([count(lines) - 1, i + 2]))
	not helpers.is_comment_line(lines[k])
])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "csrf")
	not helpers.is_test_path(path)
	not _token_api(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "csrf")
	not helpers.is_comment_line(line)
	regex.match(`\.csrf\s*\(`, _blank(line))
	_csrf_off(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_csrf_off(lines, i, _) if {
	j := _joined(lines, i)
	regex.match(`\.csrf\s*\(`, j)
	regex.match(_disable_re, j)
}

_csrf_off(_, _, line) if regex.match(_ignore_all_re, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".xml")
	contains(content, "csrf")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "csrf")
	not startswith(trim_space(line), "<!--")
	regex.match(`<(?:\w+:)?csrf\b[^>]*\bdisabled\s*=\s*["']true["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
