# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_448

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-448",
	"name": "Obsolete Feature in UI",
	"description": "Reports a Java web endpoint that is marked obsolete but still served: @Deprecated (or an OpenAPI @Operation/@ApiOperation with deprecated = true, on one line or spread over several) in the same annotation block as a Spring @*Mapping, JAX-RS @GET/@POST/.../@Path, Micronaut @Get/@Post/..., or on a @Controller/@RestController class, whether the annotations share a line or not and in either order. A deprecated endpoint usually keeps the weaker behaviour it was retired for (an old login flow, an unescaped export) and stops getting fixes, while clients and attackers can still call it. Not reported: @Deprecated on ordinary methods, fields and classes that are not mapped to a URL, an endpoint whose body answers 410 Gone or redirects to its replacement, declarative HTTP clients (@FeignClient, Micronaut @Client, MicroProfile @RegisterRestClient, @HttpExchange), Javadoc @deprecated tags, comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-448/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [448],
	"capec": [],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["obsolete", "deprecated-endpoint", "cwe-448"],
}

# @Deprecated at the start of a line or after another annotation on it.
_deprecated := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*@(?:java\.lang\.)?Deprecated\b`

_openapi_flag := `\bdeprecated\s*=\s*true\b`

_mapped := `(?:^|\s)@(?:(?:Get|Post|Put|Delete|Patch|Request)Mapping|GET|POST|PUT|DELETE|PATCH|Path|Controller|RestController|Get|Post|Put|Delete|Patch)\b`

_client_file := `@(?:FeignClient|RegisterRestClient|HttpExchange|(?:Get|Post|Put|Delete|Patch)Exchange|Client\s*\()`

_gone := `HttpStatus\.GONE|SC_GONE|Status\.GONE|\b410\b|"redirect:|MOVED_PERMANENTLY|PERMANENT_REDIRECT|sendRedirect\s*\(|Status\.MOVED|\b30[18]\b`

# A line that ends an annotation block: blank, a statement, or a brace.
_boundary(line) if trim_space(line) == ""

_boundary(line) if regex.match(`[;{}]\s*(?://.*)?$`, line)

# The block start: the line after the nearest boundary above i (at most eight up).
_start(lines, i) := s if {
	bs := [j | some j in numbers.range(max([0, i - 8]), i - 1); j < i; _boundary(lines[j])]
	count(bs) > 0
	s := max(bs) + 1
}

_start(lines, i) := max([0, i - 8]) if {
	not _has_boundary_above(lines, i)
}

_has_boundary_above(lines, i) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	j < i
	_boundary(lines[j])
}

# The block end: the declaration line (the first boundary at or below i), included,
# because annotations can share the declaration's line.
_end(lines, i) := e if {
	es := [k | some k in numbers.range(i, min([count(lines) - 1, i + 8])); _boundary(lines[k])]
	count(es) > 0
	e := es[0]
}

_block(lines, i) := concat("\n", [l |
	some j in numbers.range(_start(lines, i), _end(lines, i))
	l := lines[j]
	not helpers.is_comment_line(l)
])

_marked(lines, i, line) if regex.match(_deprecated, line)

# deprecated = true inside an @Operation(...) / @ApiOperation(...) of the same block.
_marked(lines, i, line) if {
	regex.match(_openapi_flag, regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`))
	regex.match(`@(?:Operation|ApiOperation)\s*\(`, _block(lines, i))
}

_retired(lines, i) if {
	regex.match(_gone, helpers.code_window(lines, i, 0, 12))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*@(?:java\.lang\.)?Deprecated\b|deprecated\s*=\s*true`, content)
	regex.match(`(?m)(?:^|\s)@(?:(?:Get|Post|Put|Delete|Patch|Request)Mapping|GET|POST|PUT|DELETE|PATCH|Path|Controller|RestController|Get|Post|Put|Delete|Patch)\b`, content)
	not regex.match(_client_file, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "eprecated")
	not helpers.is_comment_line(line)
	_marked(lines, i, line)
	regex.match(_mapped, _block(lines, i))
	not _retired(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A deprecated endpoint is still mapped and served: obsolete features keep the weaknesses they were retired for and stop receiving fixes. Remove the mapping or answer 410 Gone",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
