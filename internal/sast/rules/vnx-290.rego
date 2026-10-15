# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_290

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-290",
	"name": "Authentication Bypass by Spoofing",
	"description": "A trust decision is taken on a client IP read from a request header the client writes itself (X-Forwarded-For, X-Real-IP, X-Client-IP, X-Originating-IP, True-Client-IP, X-Cluster-Client-IP, CF-Connecting-IP, X-Remote-Addr/IP, or Django's META HTTP_X_FORWARDED_FOR/HTTP_X_REAL_IP; also Werkzeug's request.access_route, and a header read through a constant naming one, such as getHeader(CLIENT_IP_HEADER)), so any caller can claim to be 127.0.0.1 or an allow-listed address. Reported in Python, Java and JavaScript/TypeScript: the header value, read inline or through a variable assigned from it (or derived from such a variable, e.g. xff.split(',')[0]) in the 12 lines above, compared with a non-empty literal (==, ===, !=, .equals, .startsWith/.startswith/.endsWith), tested for membership (in ALLOWED, .includes/.contains/.has/.indexOf), passed to an is_trusted/isInternal/isAllowed-style helper, or tested with an address-class predicate (ipaddress.ip_address(ip).is_private/is_loopback, InetAddress.getByName(ip).isLoopbackAddress()/isSiteLocalAddress()); and a rate limiter keyed on the header (keyGenerator, key_func, keyResolver), which lets a brute-force client rotate the value to escape the limit. Not reported: logging or storing the header, null/empty/'unknown' checks (also as membership in (None, \"\", \"unknown\")), shape checks such as .includes(',') when splitting the list, decisions on the socket address (request.getRemoteAddr(), req.ip with Express 'trust proxy', REMOTE_ADDR), setting the header on a response or outgoing request, test code and comments. Whether a trusted reverse proxy overwrites the header before it reaches this code is deployment configuration and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-290/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [290],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["auth", "spoofing", "x-forwarded-for", "cwe-290"],
}

_is_src(path) if {
	some ext in {".py", ".java", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
}

_header_re := `(?i)["'](x-forwarded-for|x-real-ip|x-client-ip|x-originating-ip|true-client-ip|x-cluster-client-ip|cf-connecting-ip|x-remote-(addr|ip)|http_x_forwarded_for|http_x_real_ip|http_x_client_ip|http_x_originating_ip|http_true_client_ip|http_cf_connecting_ip|http_x_cluster_client_ip)["']`

_gate := `(?i)forwarded.for|real.ip|client.ip|originating.ip|connecting.ip|remote.(addr|ip)|access_route`

# Werkzeug's request.access_route is the X-Forwarded-For list.
_route_re := `\brequest\.access_route\b`

# Constants holding a header name: `CLIENT_IP_HEADER = "X-Real-IP"`.
_header_consts(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Z][A-Z0-9_]*)\s*(?::\s*\w+\s*)?=\s*`, _header_re]), content, -1)
}

# What reads the header in this file: the literal, access_route, or a read
# keyed by a constant naming it.
_src_re(content) := concat("|", array.concat([_header_re, _route_re], [concat("", [`(getHeader|get|header|getenv)\(\s*`, c, `\s*[,)]|\[\s*`, c, `\s*\]`]) | some c in _header_consts(content)]))

# The header is written, not read.
_writes_header(line) if regex.match(`(?i)\b(setHeader|addHeader|set|header|append)\(\s*["'][\w-]+["']\s*,`, line)

_writes_header(line) if regex.match(`(?i)\.headers\s*\[[^\]]+\]\s*=[^=]`, line)

# A comparison on the same line as an inline header read.
_inline_cmp := [
	`(===?|!==?)\s*["'](?:localhost|[0-9a-fA-F:./]*[\d:][0-9a-fA-F:./]*)["']`,
	`["'](?:localhost|[0-9a-fA-F:./]*[\d:][0-9a-fA-F:./]*)["']\s*(===?|!==?)\s*\S`,
	`["'](?:localhost|[0-9a-fA-F:./]*[\d:][0-9a-fA-F:./]*)["']\.equals(IgnoreCase)?\(`,
	`\.(equals|equalsIgnoreCase|startsWith|startswith|endsWith|endswith)\(\s*["'](?:localhost|[0-9a-fA-F:./]*[\d:])`,
	`\.(includes|contains|has|indexOf|__contains__)\(\s*["'](?:localhost|[0-9a-fA-F:./]*[\d:])`,
	`\.(includes|contains|has|indexOf|__contains__)\(\s*(req|request)\b`,
	`\)\s+(not\s+)?in\s+[A-Za-z_\[\(\{]`,
	`(?i)\b(is_?trusted|is_?internal|is_?allowed|is_?whitelisted|is_?allowlisted|is_?local|in_?allowlist|in_?whitelist)\w*\(`,
	`\)\s*\.(is_private|is_loopback|is_link_local|isLoopbackAddress|isSiteLocalAddress|isAnyLocalAddress|isLinkLocalAddress)\b`,
]

# Address-class predicates on the parsed value: ipaddress.ip_address(ip).is_private,
# InetAddress.getByName(ip).isLoopbackAddress().
_class_pred := `\s*\)\s*\.(is_private|is_loopback|is_link_local|isLoopbackAddress|isSiteLocalAddress|isAnyLocalAddress|isLinkLocalAddress)\b`

# Membership in a collection of only null/empty/'unknown' values is a
# presence check, not an allow-list.
_null_set := `\s(not\s+)?in\s+[\(\[\{]\s*(None|null|""|''|"unknown"|'unknown')(\s*,\s*(None|null|""|''|"unknown"|'unknown'))*\s*,?\s*[\)\]\}]`

_var_cmp(v) := [
	concat("", [`\b`, v, `\b\s*(===?|!==?)\s*["'](?:localhost|[0-9a-fA-F:./]*[\d:][0-9a-fA-F:./]*)["']`]),
	concat("", [`["'](?:localhost|[0-9a-fA-F:./]*[\d:][0-9a-fA-F:./]*)["']\s*(===?|!==?)\s*`, v, `\b`]),
	concat("", [`["'](?:localhost|[0-9a-fA-F:./]*[\d:][0-9a-fA-F:./]*)["']\.equals(IgnoreCase)?\(\s*`, v, `\s*\)`]),
	concat("", [`\b`, v, `\.(equals|equalsIgnoreCase|startsWith|startswith|endsWith|endswith)\(\s*["'](?:localhost|[0-9a-fA-F:./]*[\d:])`]),
	concat("", [`\b`, v, `\s+(not\s+)?in\s+[A-Za-z_\[\(\{]`]),
	concat("", [`\(\s*`, v, `\s*\)\s+(not\s+)?in\s+[A-Za-z_\[\(\{]`]),
	concat("", [`\.(includes|contains|has|indexOf|__contains__)\(\s*`, v, `\s*\)`]),
	concat("", [`(?i)\b(is_?trusted|is_?internal|is_?allowed|is_?whitelisted|is_?allowlisted|is_?local|in_?allowlist|in_?whitelist)\w*\(\s*`, v, `\b`]),
	concat("", [`\(\s*`, v, _class_pred]),
]

_rate_key := `\b(keyGenerator|key_?[Ff]unc|keyResolver|key_?[Gg]enerator|getKey|identifier)\b`

# Names holding the header value: assigned from it, or from such a name.
_held(lines, i, src) := hs if {
	direct := helpers.tainted_names(lines, i, 12, src)
	derived := {w |
		some v in direct
		some j in numbers.range(max([0, i - 12]), i - 1)
		not helpers.is_comment_line(lines[j])
		regex.match(concat("", [`\b`, v, `\b`]), lines[j])
		w := helpers.assigned_first(lines[j])
	}
	hs := direct | derived
}

_decides(lines, i, line, src) if {
	regex.match(src, line)
	not _writes_header(line)
	some re in _inline_cmp
	regex.match(re, line)
}

_decides(lines, i, line, src) if {
	regex.match(`==|!=|equals|startsWith|startswith|endsWith|endswith|\sin\s|includes|contains|has\(|indexOf|trusted|internal|allowed|listed|local|is_private|is_loopback|Address\(`, line)
	some v in _held(lines, i, src)
	some re in _var_cmp(v)
	regex.match(re, line)
	not _assigns(line, v)
}

# The line assigns the name rather than testing it.
_assigns(line, v) if helpers.assigned_first(line) == v

findings contains finding if {
	some path, content in input.file_contents
	_is_src(path)
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	src := _src_re(content)
	regex.match(src, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_decides(lines, i, line, src)
	not regex.match(`(?i)\b(log|logger|logging|console)\.\w+\(`, line)
	not regex.match(_null_set, line)
	finding := _finding(path, i, line, "Access is decided on a client address taken from a request header the client controls (X-Forwarded-For/X-Real-IP), so anyone can send 'X-Forwarded-For: 127.0.0.1' and pass. Use the socket address, or the address your trusted proxy appends (Express 'trust proxy', Werkzeug ProxyFix, Spring ForwardedHeaderFilter with a fixed hop count), and authenticate the caller instead of trusting its IP")
}

findings contains finding if {
	some path, content in input.file_contents
	_is_src(path)
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	regex.match(_rate_key, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_rate_key, line)
	not helpers.is_comment_line(line)
	regex.match(_header_re, helpers.code_window(lines, i, 0, 2))
	finding := _finding(path, i, line, "The rate limiter is keyed on X-Forwarded-For (or a similar client-supplied header), so a client that sends a new value with every request is never limited and can brute-force the protected endpoint. Key the limiter on the socket address or the address your trusted proxy appends, or on the account being attacked")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
