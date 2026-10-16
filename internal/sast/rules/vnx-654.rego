# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_654

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-654",
	"name": "Reliance on a Single Factor in a Security Decision",
	"description": "Access is granted on the client's network origin alone (CWE-654): an if/elif condition that tests the client address or a client-supplied origin header, request.remote_addr, request.access_route, request.client.host, REMOTE_ADDR, HTTP_X_FORWARDED_FOR, HTTP_X_REAL_IP, HTTP_REFERER, request.referrer or an X-Forwarded-For/X-Real-IP/X-Client-IP/Referer header in Python, req.ip, req.ips, Koa ctx.ip/ctx.request.ip, socket/connection .remoteAddress or those headers in JavaScript/TypeScript, directly or through a variable assigned from one a few lines above, with ==, ===, in, includes, startswith/startsWith, indexOf or a regex test, and whose branch grants access: return next(), next() or await next(), login()/login_user(), a session admin/user/authenticated flag set, an is_admin/authenticated = True assignment, return True, or a decorator returning the wrapped view. An address or header is spoofable (X-Forwarded-For, Referer) or shared (NAT, proxies, SSRF from localhost) and is not proof of identity. Not reported: a condition that also checks an authenticated user, session, token or password, negated checks and blocklists that deny, logging, rate limiting and region lookups, test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-654/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [654],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["authentication", "ip-allowlist", "single-factor", "cwe-654"],
}

_py_src := `request\.remote_addr|request\.access_route|request\.client\.host|REMOTE_ADDR|HTTP_X_FORWARDED_FOR|HTTP_X_REAL_IP|HTTP_REFERER|request\.referrer|request\.headers(?:\.get\(|\[)\s*["'](?i:x-forwarded-for|x-real-ip|x-client-ip|true-client-ip|referer)["']`

_js_src := `\breq(?:uest)?\.(?:ip|ips)\b|\bctx\.(?:request\.)?(?:ip|ips)\b|\bctx\.(?:get|header)\(\s*['"](?i:referer|referrer|x-forwarded-for|x-real-ip)['"]|\.remoteAddress\b|\breq(?:uest)?\.headers(?:\[\s*['"](?i:x-forwarded-for|x-real-ip|x-client-ip|true-client-ip|referer|referrer)['"]|\.(?:referer|referrer)\b)|\breq(?:uest)?\.(?:get|header)\(\s*['"](?i:referer|referrer|x-forwarded-for|x-real-ip)['"]`

_src(path) := _py_src if endswith(path, ".py")

_src(path) := _js_src if not endswith(path, ".py")

_exts := {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx"}

_cond := `^\s*(?:\}\s*else\s+)?(?:if|elif)\b`

_compare := `===?|\bin\b|\.includes\(|startswith\(|startsWith\(|\.indexOf\(|\.test\(`

_negated := `!==?|\bnot\s+in\b|\bnot\s|!\s*[\w.]+\.includes\(|!\s*\(|indexOf\([^)]*\)\s*(?:===?\s*-1|<\s*0)`

# The condition also asks who the caller is: not a single factor.
_second_factor := `(?i)current_user|is_authenticated|req\.user|request\.user|session|token|password|passwd|verify|auth|api_?key|signature|hmac`

_grant := `return\s+(?:await\s+)?next\(\)|^\s*(?:await\s+)?next\(\)|\blogin(?:_user)?\s*\(|\bsession\[\s*["'](?:is_?admin|admin|authenticated|logged_?in|user(?:_id)?|role)["']\s*\]\s*=[^=]|\bsession\.(?:is_?admin|isAdmin|admin|authenticated|loggedIn|user|role)\s*=[^=]|\b(?:is_?admin|isAdmin|authenticated|authorized|logged_?in|loggedIn)\s*=\s*(?:True|true)\b|return\s+(?:True|true)\b|return\s+(?:f|func|fn|view|view_func|handler)\s*\(`

_strip(line) := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'", `""`)

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The condition reads the origin directly, or a variable assigned from it.
_reads_origin(path, lines, i, line) if regex.match(_src(path), line)

_reads_origin(path, lines, i, line) if {
	some v in helpers.tainted_names(lines, i, 6, _src(path))
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

# The branch body: the rest of the condition line, and the lines after it
# indented deeper than the condition, up to four.
_grants(lines, i, line) if regex.match(_grant, substring(line, indexof(line, "if"), -1))

_grants(lines, i, line) if {
	ind := _indent(line)
	end := min([count(lines) - 1, i + 4])
	some j in numbers.range(i + 1, end)
	trim_space(lines[j]) != ""
	not helpers.is_comment_line(lines[j])
	_indent(lines[j]) > ind
	not _dedented_between(lines, i, j, ind)
	regex.match(_grant, lines[j])
}

_dedented_between(lines, i, j, ind) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	trim_space(lines[k]) != ""
	_indent(lines[k]) <= ind
}

# A nested condition before the grant is a second check.
_dedented_between(lines, i, j, _) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	regex.match(`^\s*(?:if|elif|for|while)\b`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(_src(path), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_cond, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	_reads_origin(path, lines, i, line)
	regex.match(_compare, code)
	not regex.match(_negated, code)
	not regex.match(_second_factor, code)
	_grants(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Access is granted on the client address or an origin header alone. Addresses and X-Forwarded-For/Referer are spoofable or shared; require an authenticated identity as well",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
