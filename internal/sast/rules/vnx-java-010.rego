package vulnetix.rules.vnx_java_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-010",
	"name": "Spring CSRF protection disabled",
	"description": "Spring Security's CSRF protection is switched off for a browser-facing configuration: http.csrf().disable() (also with .disable() on the next line), .csrf(c -> c.disable()), .csrf(c -> { c.disable(); }), .csrf(AbstractHttpConfigurer::disable) and other ::disable method references including WebFlux's ServerHttpSecurity.CsrfSpec::disable, CSRF ignored for every path (ignoringAntMatchers/ignoringRequestMatchers(\"/**\"), also as new AntPathRequestMatcher(\"/**\"), antMatcher(\"/**\") or AnyRequestMatcher.INSTANCE), and <csrf disabled=\"true\"/> in a Spring Security XML namespace configuration. Not reported: CSRF ignored for specific paths (a webhook, an actuator endpoint), a configuration in the same file that is stateless (SessionCreationPolicy.STATELESS) and authenticates with bearer tokens (oauth2ResourceServer, JWT or bearer-token filters), where no ambient credential exists to forge, other .disable() calls (cors, frameOptions), test configurations, and the pattern in comments or string literals.",
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

_disable_re := `\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|\.csrf\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)|\.csrf\s*\(\s*[\w.]+\s*::\s*disable\s*\)|\.csrf\s*\(\s*\w+\s*->\s*\{\s*\w+\s*\.\s*disable\s*\(\s*\)\s*;`

# Every path exempted: "/**", new AntPathRequestMatcher("/**"),
# antMatcher("/**") or AnyRequestMatcher.INSTANCE.
_ignore_all_re := `\.ignoring(?:Ant|Request|Mvc)?Matchers\s*\(\s*(?:(?:new\s+AntPathRequestMatcher\s*\(|(?:AntPathRequestMatcher\s*\.\s*)?antMatcher\s*\()\s*"/\*\*?"\s*\)|"/\*\*?"|AnyRequestMatcher\.INSTANCE)\s*\)`

# A stateless API authenticated by bearer tokens carries no ambient
# credential a forged request could ride on.
#
# Judged per filter chain: the text from the bean or configure() method that
# contains the csrf line to the next one, so a stateless /api/** chain does
# not excuse a form-login chain in the same class.
_token_api(block) if {
	regex.match(`SessionCreationPolicy\.STATELESS|NoOpServerSecurityContextRepository`, block)
	regex.match(`oauth2ResourceServer|(?i:\bjwt\w*filter\b)|\bjwt\s*\(|(?i:bearertoken\w*)`, block)
}

# A pure resource server: bearer tokens and no session-establishing login.
_token_api(block) if {
	contains(block, "oauth2ResourceServer")
	not regex.match(`\b(?:formLogin|oauth2Login|httpBasic|rememberMe|saml2Login)\s*\(`, block)
}

_decl_re := `\b(?:SecurityFilterChain|SecurityWebFilterChain)\s+\w+\s*\(|\bvoid\s+configure\s*\(`

_block(lines, i) := concat("\n", [lines[k] |
	some k in numbers.range(s, e)
	not helpers.is_comment_line(lines[k])
]) if {
	n := count(lines)
	starts := [k | some k in numbers.range(max([0, i - 80]), i); regex.match(_decl_re, lines[k])]
	ends := [k | some k in numbers.range(min([n - 1, i + 1]), min([n - 1, i + 80])); k > i; regex.match(_decl_re, lines[k])]
	s := max(array.concat(starts, [max([0, i - 80])]))
	e := min(array.concat(ends, [min([n - 1, i + 80])]))
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
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "csrf")
	not helpers.is_comment_line(line)
	regex.match(`\.csrf\s*\(`, _blank(line))
	_csrf_off(lines, i, line)
	not _token_api(_block(lines, i))
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

_csrf_off(lines, i, _) if regex.match(_ignore_all_re, _joined_raw(lines, i))

# As _joined, with string literals kept for the "/**" an exemption names.
_joined_raw(lines, i) := concat(" ", [lines[k] |
	some k in numbers.range(i, min([count(lines) - 1, i + 2]))
	not helpers.is_comment_line(lines[k])
])

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
