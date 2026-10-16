# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_931

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-931",
	"name": "Authorization rule opens every request, an admin path or a state-changing endpoint to anyone",
	"description": "CWE-931 is an OWASP Top Ten 2013 category with no code shape of its own; this rule reports the concrete missing-authorization configuration it was generated for, in Java and Kotlin: Spring Security anyRequest().permitAll() and WebFlux anyExchange().permitAll() (also split across lines, and the Kotlin DSL authorize(anyRequest/anyExchange, permitAll)); a matcher (requestMatchers, antMatchers, mvcMatchers, regexMatchers, pathMatchers or the Kotlin authorize) for \"/**\", an admin, management or internal path segment at any depth (/admin/**, /api/admin/**, also inside new AntPathRequestMatcher(...)), the whole /actuator tree or EndpointRequest.toAnyEndpoint() directly followed by permitAll() (the matcher's arguments may span several lines); web.ignoring() on such a path, which takes it out of Spring Security altogether; and a JAX-RS/Jakarta @PermitAll on a method annotated @DELETE, @PUT or @PATCH. Not reported: permitAll on public paths (login, static assets, /actuator/health, and an admin area's own login page and assets such as /admin/login or /admin/css/**), a sensitive matcher that is given a role before a later permitAll on the same line, formLogin()/logout() permitAll, @PermitAll on GET or POST methods (login and registration are public by design), StrictMode policies, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-931/",
	"languages": ["java", "kotlin"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [931],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-auth-cc", "spring-security", "cwe-931"],
}

_ext(path) if endswith(path, ".java")

_ext(path) if endswith(path, ".kt")

# A path string naming everything, an administrative/management/internal
# segment (at any depth) or the whole actuator tree.
_sensitive_path := `^"(/\*\*|(/[\w{}.*-]+)*/(admin[\w-]*|management|internal)(/[^"]*)?|/actuator(/\*\*?)?)"$`

# Public pieces of an admin area: its login page and static assets.
_public_admin := `(?i)/(admin[\w-]*|management|internal)/(login|signin|sign-in|logout|css|js|static|images?|img|assets|fonts|webjars|favicon)`

_sensitive(args) if regex.match(`EndpointRequest\s*\.\s*toAnyEndpoint\s*\(\s*\)`, args)

_sensitive(args) if {
	some s in regex.find_all_string_submatch_n(`"[^"]*"`, args, -1)
	regex.match(_sensitive_path, s[0])
	not regex.match(_public_admin, s[0])
}

_matcher := `\b(antMatchers|requestMatchers|mvcMatchers|regexMatchers|pathMatchers)\s*\(`

# Matcher arguments allowing one level of nested calls.
_args := `((?:[^()]|\([^()]*\))*)\)`

# The matcher's arguments name a sensitive path (the whole call on one line).
_sensitive_matcher(line) if {
	m := regex.find_all_string_submatch_n(concat("", [_matcher, `(.*)\)`]), line, 1)
	count(m) > 0
	_sensitive(m[0][2])
}

_open_line(line) if regex.match(`\bany(Request|Exchange)\s*\(\s*\)\s*\.\s*permitAll\s*\(`, line)

# A sensitive matcher immediately followed by .permitAll() on the same line.
_open_line(line) if {
	some m in regex.find_all_string_submatch_n(concat("", [_matcher, _args, `\s*\.\s*permitAll\s*\(`]), line, -1)
	_sensitive(m[2])
}

# web.ignoring() takes the paths out of Spring Security altogether.
_open_line(line) if {
	some m in regex.find_all_string_submatch_n(concat("", [`\.\s*ignoring\s*\(\s*\)\s*\.\s*`, _matcher, _args]), line, -1)
	_sensitive(m[2])
}

_open_line(line) if regex.match(`\bauthorize\s*\(\s*any(Request|Exchange)\s*,\s*permitAll\s*\)`, line)

_open_line(line) if {
	m := regex.find_all_string_submatch_n(`\bauthorize\s*\(\s*("[^"]*")\s*,\s*permitAll\s*\)`, line, 1)
	count(m) > 0
	_sensitive(m[0][1])
}

# `.permitAll()` alone on its line, continuing a matcher on the previous code line.
_hit(line, _, _) if _open_line(line)

_hit(line, lines, i) if {
	regex.match(`^\s*\.\s*permitAll\s*\(`, line)
	some j in numbers.range(max([0, i - 2]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	_prev_opens(prev)
}

# `.permitAll()` closing a matcher whose argument list spans several lines.
_hit(line, lines, i) if {
	regex.match(`^\s*\.\s*permitAll\s*\(`, line)
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(_matcher, lines[j])
	not helpers.is_comment_line(lines[j])
	every k in helpers.span(j + 1, i - 1) {
		not regex.match(`\b(antMatchers|requestMatchers|mvcMatchers|regexMatchers|pathMatchers)\s*\(|permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll|\.access\s*\(`, lines[k])
	}
	args := concat(" ", [l |
		some k in numbers.range(j, i - 1)
		not helpers.is_comment_line(lines[k])
		l := lines[k]
	])
	_sensitive(args)
}

_prev_opens(prev) if regex.match(`\bany(Request|Exchange)\s*\(\s*\)\s*$`, trim_space(prev))

_prev_opens(prev) if {
	not contains(prev, "permitAll")
	not regex.match(`\.\s*(authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll|access)\s*\(`, prev)
	_sensitive_matcher(prev)
}

# JAX-RS: @PermitAll in the same annotation block as @DELETE/@PUT/@PATCH.
_hit(line, lines, i) if {
	regex.match(`^\s*@PermitAll\b`, line)
	some j in numbers.range(max([0, i - 4]), min([count(lines) - 1, i + 4]))
	regex.match(`^\s*@(DELETE|PUT|PATCH)\b`, lines[j])
	_annotation_block(lines, min([i, j]), max([i, j]))
}

_annotation_block(lines, a, b) if {
	every k in numbers.range(a, b) {
		regex.match(`^\s*@`, lines[k])
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`permitAll|@PermitAll|\.ignoring\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)permitall|\.ignoring\s*\(`, line)
	not helpers.is_comment_line(line)
	regex.match(`(?i)permitall|\.ignoring\s*\(`, regex.replace(line, `"(\\.|[^"\\])*"`, `""`))
	_hit(line, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Authorization rule lets unauthenticated users reach every request, an administrative path or a state-changing endpoint. Require authentication or a role (authenticated(), hasRole(...), @RolesAllowed)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
