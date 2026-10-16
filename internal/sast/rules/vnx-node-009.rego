package vulnetix.rules.vnx_node_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-009",
	"name": "Node.js server-side request forgery",
	"description": "A server-side HTTP request whose destination comes from the incoming request: the URL (first argument, or the url/uri/host/hostname/baseURL member of an options object) of fetch, axios/axios.get/post/put/patch/delete/head/request, http(s).get/request, got, needle, superagent, undici, or the request library is a req/request query, body, params, headers or cookies value, a Koa ctx.query/ctx.request.body value, or a variable assigned (or destructured) from one in the 25 lines above, directly or through one intermediate assignment such as 'http://' + host + '/x'. Also reported: curl or wget run through spawn/spawnSync/execFile with such a value among its arguments. Not reported: a URL whose host is fixed by a constant prefix (API_BASE + '/items/' + id, `${config.apiUrl}/users/${id}`, 'https://api.example.com/...'), request values passed only as headers, query params or a body, a destination checked against an allowlist (ALLOWED_HOSTS, isAllowed..., ssrf filter agents) in the lines above, method calls named fetch/request on other objects (cache.fetch), browser code without a server request object, comments and string literals. Flows through helper functions or across files are not followed. A request whose response is sent back to the client (res.send/json/write/end of it, a pipe to res, ctx.body) is reported by VNX-441 instead, the open-proxy form of SSRF, so one request is one finding; Python SSRF is VNX-918.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-009/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ssrf", "web", "cloud"],
}

_msg := "Server-side HTTP request to a destination taken from the incoming request (SSRF): an attacker can reach internal services or cloud metadata (169.254.169.254). Resolve the URL and check its scheme and host against an allowlist before requesting it"

_is_js(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

# Request values a client controls. req.url/req.path are left out: they name
# a path on this server, and a proxy forwarding them keeps its own host.
_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies|payload)\b|\breq\.(?:param|get|header)\s*\(|\bctx\.(?:request\.)?(?:query|body|params|headers|querystring)\b`

_file_gate := `(?m)\b(?:fetch|axios|https?\.(?:get|request)|got|needle|superagent|undici|request|curl|wget)\b`

# String contents blanked, so a sink spelled inside a quote is not a call.
# A quoted string holding ${ is the inside of a template literal (`a '${x}'`)
# and is kept, so the interpolation stays visible.
_blank(s) := regex.replace(s, `'(?:[^'\\$]|\\.|\$[^{'])*'|"(?:[^"\\$]|\\.|\$[^{"])*"`, "''")

_sinks := [
	`(?:^|[^\w.$])(?:window\.|globalThis\.)?fetch\s*\(`,
	`(?:^|[^\w.$])axios(?:\.(?:get|post|put|patch|delete|head|options|request))?\s*\(`,
	`(?:^|[^\w.$])https?\.(?:get|request)\s*\(`,
	`(?:^|[^\w.$])got(?:\.(?:get|post|put|patch|delete|head|stream))?\s*\(`,
	`(?:^|[^\w.$])(?:needle|superagent|undici)(?:\.(?:get|post|put|patch|del|delete|head|request))?\s*\(`,
]

_request_lib_sink := `(?:^|[^\w.$])(?:request|rp)(?:\.(?:get|post|put|patch|del|head))?\s*\(`

_uses_request_lib(content) if regex.match(`require\(\s*['"](?:request|request-promise(?:-native)?)['"]\s*\)|from\s+['"](?:request|request-promise(?:-native)?)['"]`, content)

_sinks_for(content) := array.concat(_sinks, [_request_lib_sink]) if _uses_request_lib(content)

_sinks_for(content) := _sinks if not _uses_request_lib(content)

_opens(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The call's text after its opening parenthesis, continued over at most six further lines
# while its parentheses are open.
_call_text(lines, i, rest) := rest if _opens(rest) < 0

_call_text(lines, i, rest) := t if {
	_opens(rest) >= 0
	last := min([count(lines) - 1, i + 6])
	last >= i + 1
	t := concat(" ", array.concat([rest], array.slice(lines, i + 1, last + 1)))
}

_call_text(lines, i, rest) := rest if {
	_opens(rest) >= 0
	i + 1 > count(lines) - 1
}

# The first top-level argument: strings, template literals and bracketed
# groups (two levels deep) are taken whole, so a comma inside them does not
# end it.
_arg_re := "^(?:'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`(?:[^`\\\\]|\\\\.)*`|\\((?:[^()]|\\([^()]*\\))*\\)|\\[(?:[^\\[\\]]|\\[[^\\[\\]]*\\])*\\]|\\{(?:[^{}]|\\{[^{}]*\\})*\\}|[^,()\\[\\]{}'\"`])*"

_first_arg(t) := a if {
	ms := regex.find_n(_arg_re, trim_left(t, " \t"), 1)
	count(ms) > 0
	a := ms[0]
}

_first_arg(t) := "" if {
	count(regex.find_n(_arg_re, trim_left(t, " \t"), 1)) == 0
}

# The part of the first argument that names the destination: the whole
# expression, or for an options object its url-like members.
_dest(a) := a if not startswith(trim_space(a), "{")

_dest(a) := d if {
	startswith(trim_space(a), "{")
	vals := [m[1] | some m in regex.find_all_string_submatch_n(`\b(?:url|uri|host|hostname|baseURL|baseUrl|href)\s*:\s*([^,}]*)`, a, -1)]
	short := [m[1] | some m in regex.find_all_string_submatch_n(`[{,]\s*(url|uri|host|hostname|href)\s*[,}]`, a, -1)]
	d := concat(" ", array.concat(vals, short))
}

_refs(text, names) if {
	some n in names
	contains(text, n)
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `(?:\s*$|\s*[^\s:\w$])`]), text)
}

_binding(item) := v if {
	lhs := trim_space(split(item, "=")[0])
	parts := split(lhs, ":")
	v := trim_left(trim_space(parts[count(parts) - 1]), ".")
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

_destructured(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	contains(l, "{")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*(.*)$`, l, 1)
	count(m) > 0
	regex.match(_src, m[0][2])
	some item in split(m[0][1], ",")
	v := _binding(item)
}

_t1(lines, i) := helpers.tainted_names(lines, i, 25, _src) | _destructured(lines, i)

# One further hop: a variable assigned from an expression that uses a
# tainted name, unless that expression pins the host.
_tainted(lines, i) := t if {
	t1 := _t1(lines, i)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		_refs(l, t1)
		v := helpers.assigned_first(l)
		rhs := substring(l, indexof(l, "=") + 1, -1)
		not _fixed_host(rhs, t1)
	}
	t := t1 | t2
}

# The destination's host is fixed before any request value is spliced in.
_fixed_host(a, _) if regex.match("^\\s*(?:new\\s+URL\\s*\\(\\s*)?['\"`]https?://[^'\"`$/]+/", a)

_fixed_host(a, names) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$.]*)\s*\+`, a, 1)
	count(m) > 0
	not _is_tainted_expr(m[0][1], names)
}

_fixed_host(a, names) if {
	m := regex.find_all_string_submatch_n("^\\s*`\\$\\{\\s*([A-Za-z_$][\\w$.]*)\\s*\\}", a, 1)
	count(m) > 0
	not _is_tainted_expr(m[0][1], names)
}

_is_tainted_expr(e, _) if regex.match(_src, e)

_is_tainted_expr(e, names) if {
	root := split(e, ".")[0]
	root in names
}

_reaches(dest, _, _) if regex.match(_src, dest)

_reaches(dest, lines, i) if _refs(dest, _tainted(lines, i))

_guard_re := `(?i)allow(?:ed)?[_-]?(?:list|hosts?|domains?|origins?|urls?)|white[_-]?list|\bisAllowed\w*\s*\(|\bis(?:Safe|Valid|Trusted)(?:Url|Host|Uri)\s*\(|\bvalidate(?:Url|Host|Uri)\s*\(|ssrf[_-]?(?:filter|agent|guard|req)|request-filtering-agent`

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 25, 0))

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _blank(line)
	some sink in _sinks_for(content)
	regex.match(sink, code)
	parts := regex.split(sink, line)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _call_text(lines, i, rest)
	a := _first_arg(t)
	dest := _dest(a)
	dest != ""
	not _fixed_host(a, _t1(lines, i))
	_reaches(dest, lines, i)
	not _guarded(lines, i)
	not _relay_owned(path, content, lines, i, line)
	finding := _finding(path, i, line)
}

# curl/wget run as a subprocess with a request value among its arguments.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:curl|wget)\b`, content)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w.$])(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*['"](?:curl|wget)['"]`, line)
	t := _call_text(lines, i, substring(line, indexof(line, "(") + 1, -1))
	_reaches(t, lines, i)
	not _guarded(lines, i)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── A fetch whose response is relayed back is VNX-441's ─────────────────
#
# When the response of the forged request is sent back to the client the
# service is an open proxy, reported by VNX-441 (CWE-441, of which SSRF is the
# child). These are that rule's tests, so a line leaves this rule only where
# VNX-441 reports it.

_rl_source := `\b(?:req|request|ctx\.request|ctx)\.(?:query|body|params|headers|cookies)\b`

_rl_sink := `(?:\baxios|\bneedle|\bgot|\bsuperagent|\bhttps?)(?:\.(?:get|post|put|patch|delete|head|request))?\s*\(|(?:^|[^\w.])(?:fetch|request|nodeFetch)\s*\(`

_rl_relay := `\.pipe\(\s*(?:res|response|reply)\b|\b(?:res|response|reply)(?:\.status\([^)]*\))?\.(?:send|write|end|json)\s*\(\s*(?:await\s+)?[A-Za-z_$][\w$]*(?:\.(?:data|body|text\(\)|json\(\)|buffer\(\)))?\s*[,)]|\bctx\.body\s*=\s*(?:await\s+)?[A-Za-z_$]`

_rl_guard := `(?i)allow(?:ed)?_?(?:list|hosts?|domains?|origins?|urls?)|whitelist|is_?allowed|is_?safe_?url|validate_?url|url_has_allowed_host`

_relay_owned(path, content, lines, i, line) if {
	regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)
	not helpers.is_test_path(path)
	regex.match(`(?m)(?:requests|httpx|urlopen|axios|needle|got|superagent|fetch|request|http)\s*[\.(]`, content)
	regex.match(_rl_source, content)
	regex.match(_rl_sink, line)
	not regex.match(concat("", [`["'][^"']*(?:`, _rl_sink, `)`]), line)
	arg := _rl_url_arg(lines, i, line)
	_rl_tainted(lines, i, arg)
	not _rl_fixed_host(arg)
	not regex.match(_rl_guard, helpers.code_window(lines, i, 12, 0))
	_rl_relayed(lines, i)
}

_rl_url_arg(lines, i, line) := arg if {
	m := regex.find_all_string_submatch_n(concat("", ["(", _rl_sink, ")(.*)$"]), line, 1)
	rest0 := m[0][count(m[0]) - 1]
	rest := _rl_continued(lines, i, rest0)
	parts := split(rest, ",")
	arg := _rl_pick(m[0][1], parts)
}

_rl_continued(_, _, rest) := rest if trim_space(rest) != ""

_rl_continued(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_rl_pick(call, parts) := concat(",", array.slice(parts, 0, 2)) if {
	endswith(call, ".request(")
	count(parts) > 1
}

_rl_pick(call, parts) := parts[0] if not _rl_two_args(call, parts)

_rl_two_args(call, parts) if {
	endswith(call, ".request(")
	count(parts) > 1
}

_rl_tainted(_, _, arg) if regex.match(_rl_source, arg)

_rl_tainted(lines, i, arg) if {
	some v in helpers.tainted_names(lines, i, 12, _rl_source)
	regex.match(concat("", [`\b`, v, `\b`]), arg)
}

_rl_tainted(lines, i, arg) if {
	some j in numbers.range(max([0, i - 12]), i - 1)
	prev := lines[j]
	regex.match(_rl_source, prev)
	not helpers.is_comment_line(prev)
	some v in _rl_declared(prev)
	regex.match(concat("", [`\b`, v, `\b`]), arg)
}

_rl_declared(line) := _rl_destructured(line) | _rl_ts_typed(line)

_rl_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`\b(?:const|let|var)\s*\{([^}]*)\}\s*=[^=]`, line, 1)
	some part in split(m[0][1], ",")
	pieces := split(trim_space(part), ":")
	n := trim_space(pieces[count(pieces) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, n)
}

_rl_ts_typed(line) := {m[0][1] |
	m := regex.find_all_string_submatch_n(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[^=]+=[^=>]`, line, 1)
	count(m) > 0
}

_rl_fixed_host(arg) if regex.match("^\\s*(?:f|r|fr|rf)?[\"'`]https?://[^/{}$\"'`\\s]+/", arg)

_rl_fixed_host(arg) if regex.match("^\\s*(?:f[\"']\\{|`\\$\\{)[A-Z][A-Z0-9_]*\\}/", arg)

_rl_fixed_host(arg) if regex.match("^\\s*[A-Z][A-Z0-9_]*(?:\\.[A-Za-z_]\\w*)?\\s*\\+\\s*[\"'`]/", arg)

_rl_relayed(lines, i) if {
	some k in numbers.range(i, _rl_end(lines, i))
	not helpers.is_comment_line(lines[k])
	regex.match(_rl_relay, lines[k])
}

_rl_handler_start := "^\\s*(?:@|(?:async\\s+)?def\\s|exports\\.[\\w$]+\\s*=|module\\.exports\\b|(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\b|(?:app|router|[\\w$]*[Rr]outer|fastify|server)\\.(?:get|post|put|patch|delete|all|route)\\s*\\(\\s*['\"`/])"

_rl_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 15])
	bs := [k | some k in numbers.range(i + 1, last); k > i; regex.match(_rl_handler_start, lines[k])]
	e := _rl_end_at(bs, last)
}

_rl_end_at(bs, _) := bs[0] - 1 if count(bs) > 0

_rl_end_at(bs, last) := last if count(bs) == 0
