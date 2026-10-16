# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_935

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-935",
	"name": "Administrative endpoint declared without a function-level access check",
	"description": "CWE-935 is the OWASP Top Ten 2013 category 'Missing Function Level Access Control'. This rule reports the shape of it that only an annotation can produce: a Spring or JAX-RS handler (Java and Kotlin) mapped to a path that names an administrative function (an /admin, /administrator, /superadmin, /sysadmin, /management, /manage, /backoffice or /staff path segment) and annotated @PermitAll, @PreAuthorize(\"permitAll()\"), @Secured(\"IS_AUTHENTICATED_ANONYMOUSLY\") or @AnonymousAllowed, which explicitly opens the function to everyone. Not reported: Spring handlers without such an annotation (Spring Security is configured centrally and VNX-931 judges that configuration), handlers that require a role, non-admin paths, test files, comments and string literals. An administrative route registered with nothing in front of it is reported by VNX-306 for Python (Flask, FastAPI) and by VNX-425 for JavaScript, TypeScript and Go (Express, Koa, Fastify, net/http, gin, echo), so one route is one finding.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-935/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [935],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["access-control", "authorization", "cwe-935"],
}

_admin_path := `(?i)(^|/)(admin|administrator|superadmin|sysadmin|management|manage|backoffice|staff)([/_\-:.]|$)`

_strip_strings(line) := regex.replace(line, "\"([^\"\\\\]|\\\\.)*\"|'([^'\\\\]|\\\\.)*'|`([^`\\\\]|\\\\.)*`", `""`)

# Java and Kotlin only. The same defect on an Express, Koa or Go route is
# reported by VNX-425 and on a Flask or FastAPI route by VNX-306, so one route
# is one finding. What this rule adds is the handler that an annotation opens
# to everyone.

# ── Spring / JAX-RS ───────────────────────────────────────────────────────

_open_anno := `^\s*@(PermitAll\b|PreAuthorize\(\s*"permitAll\(\)"\s*\)|Secured\(\s*\{?\s*"IS_AUTHENTICATED_ANONYMOUSLY"|AnonymousAllowed\b)`

_mapping := `@(?:(?:Get|Post|Put|Delete|Patch|Request)Mapping|Path)\s*\((.*)\)`

_jvm_findings contains [path, i] if {
	some path, content in input.file_contents
	regex.match(`\.(java|kt)$`, path)
	not helpers.is_test_path(path)
	regex.match(`PermitAll|permitAll\(\)|IS_AUTHENTICATED_ANONYMOUSLY|AnonymousAllowed`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_open_anno, line)
	some k in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	_same_annotation_block(lines, k, i)
	m := regex.find_all_string_submatch_n(_mapping, lines[k], 1)
	count(m) > 0
	some lit in regex.find_all_string_submatch_n(`"([^"]*)"`, m[0][1], -1)
	regex.match(_admin_path, lit[1])
}

# Every line between the mapping and the annotation is itself an annotation.
_same_annotation_block(lines, k, i) if {
	k != i
	lo := min([k, i])
	hi := max([k, i])
	not _non_annotation_between(lines, lo, hi)
}

_non_annotation_between(lines, lo, hi) if {
	lo + 1 <= hi - 1
	some x in helpers.span(lo + 1, hi - 1)
	not regex.match(`^\s*@`, lines[x])
}

_message :="Administrative endpoint is reachable without a function-level access check: any caller can invoke it. Add an authorization middleware, decorator or role annotation (and check the role on the server)"

findings contains finding if {
	some [path, i] in _jvm_findings
	lines := split(input.file_contents[path], "\n")
	not regex.match(`^\s*$`, _strip_strings(lines[i]))
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
