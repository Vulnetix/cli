# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_441

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-441",
	"name": "Unintended proxy: request-chosen URL fetched and relayed to the client",
	"description": "Reports a server-side HTTP fetch whose URL (the first argument, or the URL argument of requests.request/http.request) is a request value, directly or through a variable assigned from one in the 12 lines above (including JS destructuring and TypeScript-annotated declarations), when the fetched response is then returned to the caller in the next 15 lines, before the next handler or function starts: Python requests/httpx/urlopen with the response's content/text/read() returned, rendered or wrapped in a Response, and Node axios/fetch/got/needle/superagent/request with the body sent, written or piped to res. Also reports http-proxy's proxy.web/proxy.ws with a target taken from the request. The service then acts as an open proxy (confused deputy) that reaches internal hosts on the requester's behalf. Not reported: a fetch whose URL is a constant (a request value only in params or the body), a URL that names a fixed host and takes only its path or query from the request (f\"{API}/items/{id}\", `${UPSTREAM}/search?q=${q}`), a fetch whose response is not relayed (plain SSRF is VNX-918 in Python and VNX-NODE-009 in JavaScript, which leave relayed fetches to this rule so one request is one finding), a flow guarded by an allow-list or URL validation between source and fetch, comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-441/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [441],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["confused-deputy", "open-proxy", "ssrf", "cwe-441"],
}

_py_source := `\brequest\.(?:args|form|values|GET|POST|json|data|query_params|path_params|params|headers|cookies|get_json\(|body|query)\b`

_js_source := `\b(?:req|request|ctx\.request|ctx)\.(?:query|body|params|headers|cookies)\b`

_py_sink := `(?:\brequests|\bhttpx|\bsession|\bsess|\bhttp|\bclient)\.(?:get|post|put|patch|delete|head|request|stream)\(|\burlopen\(`

_js_sink := `(?:\baxios|\bneedle|\bgot|\bsuperagent|\bhttps?)(?:\.(?:get|post|put|patch|delete|head|request))?\s*\(|(?:^|[^\w.])(?:fetch|request|nodeFetch)\s*\(`

_py_relay := `(?:\breturn\b|Response\(|render\(|jsonify\(|make_response\().*\.(?:content|text|raw|read\(\)|json\(\)|iter_content\()`

_js_relay := `\.pipe\(\s*(?:res|response|reply)\b|\b(?:res|response|reply)(?:\.status\([^)]*\))?\.(?:send|write|end|json)\s*\(\s*(?:await\s+)?[A-Za-z_$][\w$]*(?:\.(?:data|body|text\(\)|json\(\)|buffer\(\)))?\s*[,)]|\bctx\.body\s*=\s*(?:await\s+)?[A-Za-z_$]`

_guard := `(?i)allow(?:ed)?_?(?:list|hosts?|domains?|origins?|urls?)|whitelist|is_?allowed|is_?safe_?url|validate_?url|url_has_allowed_host`

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)

_source("py") := _py_source

_source("js") := _js_source

_sink("py") := _py_sink

_sink("js") := _js_sink

_relay("py") := _py_relay

_relay("js") := _js_relay

# The URL argument of the call that starts at the sink match: the text after
# the opening parenthesis (continued onto the next line when the call breaks
# after it), cut at the first comma. requests.request("GET", url) names the URL
# second.
_url_arg(lines, i, line, sink_re) := arg if {
	m := regex.find_all_string_submatch_n(concat("", ["(", sink_re, ")(.*)$"]), line, 1)
	rest0 := m[0][count(m[0]) - 1]
	rest := _continued(lines, i, rest0)
	parts := split(rest, ",")
	arg := _pick(m[0][1], parts)
}

_continued(lines, i, rest) := r if {
	trim_space(rest) != ""
	r := rest
}

_continued(lines, i, rest) := r if {
	trim_space(rest) == ""
	i + 1 < count(lines)
	r := lines[i + 1]
}

_pick(call, parts) := concat(",", array.slice(parts, 0, 2)) if {
	endswith(call, ".request(")
	count(parts) > 1
}

_pick(call, parts) := parts[0] if not _two_args(call, parts)

_two_args(call, parts) if {
	endswith(call, ".request(")
	count(parts) > 1
}

_tainted_arg(lines, i, arg, lang) if regex.match(_source(lang), arg)

_tainted_arg(lines, i, arg, lang) if {
	some v in helpers.tainted_names(lines, i, 12, _source(lang))
	regex.match(concat("", [`\b`, v, `\b`]), arg)
}

# const { url, page } = req.query; and const url: string = req.query.u (TypeScript),
# neither of which the shared assignment helper reads.
_tainted_arg(lines, i, arg, "js") if {
	some j in numbers.range(max([0, i - 12]), i - 1)
	prev := lines[j]
	regex.match(_js_source, prev)
	not helpers.is_comment_line(prev)
	some v in _js_declared(prev)
	regex.match(concat("", [`\b`, v, `\b`]), arg)
}

_js_declared(line) := _js_destructured(line) | _ts_typed(line)

_js_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`\b(?:const|let|var)\s*\{([^}]*)\}\s*=[^=]`, line, 1)
	some part in split(m[0][1], ",")
	pieces := split(trim_space(part), ":")
	n := trim_space(pieces[count(pieces) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, n)
}

_ts_typed(line) := {m[0][1] |
	m := regex.find_all_string_submatch_n(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[^=]+=[^=>]`, line, 1)
	count(m) > 0
}

# An allow-list or URL validation in the lines between the request read and the fetch.
_guarded(lines, i) if {
	regex.match(_guard, helpers.code_window(lines, i, 12, 0))
}

# The relay must come before the next handler starts: the response of a
# webhook POST is not relayed by the res.json() of the route declared below it.
_handler_start := "^\\s*(?:@|(?:async\\s+)?def\\s|exports\\.[\\w$]+\\s*=|module\\.exports\\b|(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\b|(?:app|router|[\\w$]*[Rr]outer|fastify|server)\\.(?:get|post|put|patch|delete|all|route)\\s*\\(\\s*['\"`/])"

_relay_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 15])
	bs := [k | some k in numbers.range(i + 1, last); k > i; regex.match(_handler_start, lines[k])]
	e := _end_at(bs, last)
}

_end_at(bs, _) := bs[0] - 1 if count(bs) > 0

_end_at(bs, last) := last if count(bs) == 0

_relayed(lines, i, lang) if {
	some k in numbers.range(i, _relay_end(lines, i))
	not helpers.is_comment_line(lines[k])
	regex.match(_relay(lang), lines[k])
}

# return Response(
#     upstream.content, ...): the wrapper opens on one line, the body is the next.
_relayed(lines, i, "py") if {
	end := _relay_end(lines, i)
	some k in numbers.range(i, end)
	not helpers.is_comment_line(lines[k])
	regex.match(`(?:\breturn\b|Response\(|render\(|jsonify\(|make_response\()\s*\(?\s*$`, lines[k])
	k + 1 <= end
	regex.match(`^\s*(?:await\s+)?[A-Za-z_][\w.]*\.(?:content|text|raw|read\(\)|json\(\)|iter_content\()`, lines[k + 1])
}

# body = await resp.read() / data = r.content, then return web.Response(body=body).
_relayed(lines, i, "py") if {
	end := _relay_end(lines, i)
	some k in numbers.range(i, end)
	regex.match(`=\s*(?:await\s+)?[A-Za-z_][\w.]*\.(?:content|text|raw|read\(\)|json\(\))\s*$`, lines[k])
	v := helpers.assigned_first(lines[k])
	k + 1 <= end
	some k2 in numbers.range(k + 1, min([end, k + 8]))
	not helpers.is_comment_line(lines[k2])
	regex.match(concat("", [`(?:\breturn\b|Response\(|render\(|jsonify\(|make_response\().*\b`, v, `\b`]), lines[k2])
}

# The URL names a fixed host and only a later part comes from the request:
# f"{API}/items/{id}", `${UPSTREAM}/q=${q}`, "https://api.example.com/" + id,
# BASE + "/x/" + id. The request cannot choose where the request goes.
_fixed_host(arg) if regex.match("^\\s*(?:f|r|fr|rf)?[\"'`]https?://[^/{}$\"'`\\s]+/", arg)

_fixed_host(arg) if regex.match("^\\s*(?:f[\"']\\{|`\\$\\{)[A-Z][A-Z0-9_]*\\}/", arg)

_fixed_host(arg) if regex.match("^\\s*[A-Z][A-Z0-9_]*(?:\\.[A-Za-z_]\\w*)?\\s*\\+\\s*[\"'`]/", arg)

_in_string(line, sink_re) if {
	regex.match(concat("", [`["'][^"']*(?:`, sink_re, `)`]), line)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	regex.match(`(?m)(?:requests|httpx|urlopen|axios|needle|got|superagent|fetch|request|http)\s*[\.(]`, content)
	regex.match(_source(lang), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink(lang), line)
	not helpers.is_comment_line(line)
	not _in_string(line, _sink(lang))
	arg := _url_arg(lines, i, line, _sink(lang))
	_tainted_arg(lines, i, arg, lang)
	not _fixed_host(arg)
	not _guarded(lines, i)
	_relayed(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "A URL taken from the request is fetched and the response relayed to the caller: the service is an open proxy into its own network. Restrict targets to an allow-list of hosts",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# http-proxy: proxy.web(req, res, { target: <request value> }).
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	not helpers.is_test_path(path)
	regex.match(`\bproxy\.(?:web|ws)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bproxy\.(?:web|ws)\s*\(`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\btarget\s*:\s*([^,}]+)`, helpers.code_window(lines, i, 0, 3), 1)
	_tainted_arg(lines, i, m[0][1], "js")
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "http-proxy forwards to a target taken from the request: the service is an open proxy into its own network. Route only to fixed upstreams",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
