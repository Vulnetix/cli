# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_444

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-444",
	"name": "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')",
	"description": "Reports the two code shapes that make HTTP framing ambiguous: Node's lenient parser switched on (insecureHTTPParser: true in http/https createServer or request options, or --insecure-http-parser in a script or NODE_OPTIONS), and a message given both a Transfer-Encoding and a Content-Length header (setHeader/putheader/header calls or header-object keys within five lines of each other, or a raw HTTP string carrying both). Either lets a proxy and a server disagree about where a request ends, so a smuggled request rides inside another. Not reported: insecureHTTPParser: false, Transfer-Encoding set after removing Content-Length, the two headers set in alternative branches (if/else, elif, switch cases, or a branch that returns before the other is set), code that reads or compares the two headers (a check that rejects both is the mitigation), comments and prose strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-444/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [444],
	"capec": ["CAPEC-33"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["http-smuggling", "cwe-444"],
}

_js(path) if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)

_code(path) if _js(path)

_code(path) if endswith(path, ".py")

_lenient_file(path) if _js(path)

_lenient_file(path) if endswith(path, "package.json")

_lenient := `\binsecureHTTPParser\s*:\s*true\b|--insecure-http-parser\b`

# A header set: a setter call, an object/dict key with a value, or an index assignment.
_set_re(name) := concat("", [
	`(?i)(?:\b(?:setHeader|set|header|append|putHeader|putheader|add_header|writeHeader)\s*\(\s*['"]`, name, `['"]\s*,`,
	`|['"]`, name, `['"]\s*:\s*['"\w\[(]`,
	`|\[\s*['"]`, name, `['"]\s*\]\s*=[^=]`,
	`)`,
])

_te_set := _set_re("transfer-encoding")

_cl_set := _set_re("content-length")

_raw_both := `(?i)content-length:\s*\d+[^"']*transfer-encoding:\s*\w|transfer-encoding:\s*\w+[^"']*content-length:\s*\d`

_cl_removed := `(?i)(?:removeHeader|delete|del|pop|unset|remove)\b[\s(]*(?:\w+(?:\.\w+)*)?\s*[\[(]?\s*['"]content-length['"]`

findings contains finding if {
	some path, content in input.file_contents
	_lenient_file(path)
	regex.match(`insecureHTTPParser|insecure-http-parser`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_lenient, line)
	not helpers.is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Node's lenient HTTP parser is enabled: it accepts malformed framing that a front-end proxy reads differently, enabling request smuggling. Remove insecureHTTPParser / --insecure-http-parser",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_code(path)
	regex.match(`(?i)transfer-encoding`, content)
	regex.match(`(?i)content-length`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)transfer-encoding`, line)
	not helpers.is_comment_line(line)
	_both(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "The message carries both Transfer-Encoding and Content-Length: servers and proxies resolve the conflict differently, which is the basis of HTTP request smuggling. Send one framing header only",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_both(_, _, line) if regex.match(_raw_both, line)

# Content-Length set on a nearby line in the same branch: an else/elif/case
# between the two settings makes them alternatives (chunked when the length is
# unknown), which is the correct way to frame a body.
_both(lines, i, line) if {
	regex.match(_te_set, line)
	some k in numbers.range(max([0, i - 5]), min([count(lines) - 1, i + 5]))
	_cl_line(lines, i, k)
	not _exclusive(lines, i, k)
	not regex.match(_cl_removed, helpers.code_window(lines, i, 5, 5))
}

_cl_line(lines, i, i) if regex.match(_cl_set, lines[i])

_cl_line(lines, i, k) if {
	k != i
	not helpers.is_comment_line(lines[k])
	regex.match(_cl_set, lines[k])
}

_exclusive(lines, i, k) if {
	some j in numbers.range(min([i, k]), max([i, k]))
	regex.match(`^\s*(?:\}\s*)?(?:else\b|elif\b|case\b|default\s*:)`, lines[j])
}

# The first setting's branch ends the function before the second runs:
# if (streaming) { res.setHeader("Transfer-Encoding", "chunked"); ...; return; }
_exclusive(lines, i, k) if {
	some j in numbers.range(min([i, k]) + 1, max([i, k]) - 1)
	regex.match(`^\s*(?:return|raise|throw|break|continue)\b`, lines[j])
}
