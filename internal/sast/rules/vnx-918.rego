# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_918

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-918",
	"name": "Server-Side Request Forgery (SSRF)",
	"description": "The destination of a server-side HTTP request comes from the incoming request, so a client can make the server call internal services, cloud metadata endpoints or arbitrary hosts (CWE-918). Reported in Python: the URL argument of requests.get/post/put/patch/delete/head/options, requests/httpx.request and .stream (method first), httpx.get/post/put/patch/delete/head, the same methods on a requests.Session(), httpx.Client()/AsyncClient() or aiohttp.ClientSession() object created in the file (assigned or bound with `as`), urllib.request.urlopen/urlopen and urllib.request.Request; in JavaScript/TypeScript: fetch, axios / axios.get/post/put/patch/delete/head/request, got and needle (bare or .get/.post/...), superagent.get/post and http(s).get/request, and for a call given an options object the url/baseURL/uri/host/hostname member within the next six lines (axios({ url: req.body.link })). The URL must be request data (Flask/Django/DRF request.args/form/values/json/data/GET/POST/headers/cookies/query_params/get_json(); Express/Koa req or request query/body/params/headers/cookies, ctx.query) inline, interpolated into the host (f\"http://{host}/x\", `https://${host}/`), concatenated after a bare scheme, or through a variable assigned or destructured from it in the 20 lines above (one further assignment, such as base + '/notify', is followed); arguments on the line after an open call are read. Not reported: a URL whose host is fixed by a literal prefix ('https://api.example.com/users/' + id) or by an UPPER_CASE, settings.* or config.* base, request data passed only as query params, body or headers, a destination checked against an allow-list (ALLOWED_HOSTS, is_safe_url, allowlist, an *ssrf*() check call) in the 12 lines above (a def/function line naming one does not count), URLs from the environment or configuration, comments and string literals. Overlaps VNX-NODE-009 for JavaScript.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-918/",
	"languages": ["node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ssrf", "cwe-918"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_src("py") := `\brequest\.(?:args|form|values|json|data|GET|POST|headers|cookies|COOKIES|query_params|get_json\()`

_src("js") := `\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|params|request\.body)\b`

# Sinks whose URL is the first argument.
_sink("py") := `\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|stream)\s*\(|(?:^|[^\w\.]|\burllib\.request\.|\brequest\.)urlopen\s*\(|\burllib\.request\.Request\s*\(`

_sink("js") := `(?:^|[^\w\.])fetch\s*\(|\baxios(?:\.(?:get|post|put|patch|delete|head|request))?\s*\(|(?:^|[^\w\.])(?:got|needle)\s*\(|\b(?:got|needle)\.(?:get|post|put|patch|delete|head|request)\s*\(|\bsuperagent\.(?:get|post|put|delete)\s*\(|\bhttps?\.(?:get|request)\s*\(`

# requests.request("GET", url) / httpx.request(method, url): URL second.
_sink2 := `\b(?:requests|httpx)\.(?:request|stream)\s*\(\s*[^,()]+,`

# Python client objects: s = requests.Session(), httpx.Client() / AsyncClient()
# (assigned or bound with `as`), aiohttp.ClientSession().
_client_ctor := `(?:requests\.[Ss]ession|httpx\.(?:Async)?Client|aiohttp\.ClientSession)\s*\(`

_py_clients(content) := set() if not regex.match(_client_ctor, content)

_py_clients(content) := _clients(content) if regex.match(_client_ctor, content)

_clients(content) := {n |
	some re in [
		concat("", [`\b([A-Za-z_]\w*)\s*=\s*(?:await\s+)?`, _client_ctor]),
		concat("", [_client_ctor, `[^)\n]*\)\s+as\s+([A-Za-z_]\w*)`]),
	]
	some m in regex.find_all_string_submatch_n(re, content, -1)
	n := m[1]
}

# [first-argument sink, second-argument sink] for one file.
_sinks(content, "py") := [_sink("py"), _sink2] if count(_py_clients(content)) == 0

_sinks(content, "py") := [f, s] if {
	cs := _py_clients(content)
	count(cs) > 0
	names := concat("|", cs)
	f := concat("", [_sink("py"), `|\b(?:`, names, `)\.(?:get|post|put|patch|delete|head|options)\s*\(`])
	s := concat("", [`\b(?:requests|httpx|`, names, `)\.(?:request|stream)\s*\(\s*[^,()]+,`])
}

_sinks(_, "js") := [_sink("js"), `a^`]

_guard := `(?i)allow_?list|allowed_?(?:hosts|domains|urls|origins)|whitelist|is_safe_url|is_allowed|isallowed|url_has_allowed_host|validate_url|\w*ssrf\w*\s*\(`

# The URL argument: the text after the sink up to the first top-level comma
# or closing parenthesis, read on the next line when the call opens empty.
_arg(lines, i, line, re) := a if {
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	rest := substring(line, indexof(line, m[0][0]) + count(m[0][0]), -1)
	txt := _with_next(lines, i, rest)
	am := regex.find_all_string_submatch_n(`^\s*((?:[^,()]|\((?:[^()]|\([^()]*\))*\))*)`, txt, 1)
	a := trim_space(am[0][1])
	a != ""
}

_with_next(lines, i, rest) := rest if trim_space(rest) != ""

_with_next(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# The destination expressions of a sink call: the URL argument, or, when the
# call takes an options object (axios({ url }), http.request({ host })), the
# url/baseURL/host/hostname member of it within the next six lines.
_url_args(lines, i, line, sinks) := {d |
	some re in sinks
	regex.match(re, line)
	a := _arg(lines, i, line, re)
	some d in _dest(lines, i, a)
}

_dest(_, _, a) := {a} if not startswith(a, "{")

_dest(lines, i, a) := ds if {
	startswith(a, "{")
	ds := _obj_dests(lines, i)
}

_obj_dests(lines, i) := {d |
	txt := concat("\n", array.slice(lines, i, i + 7))
	some m in regex.find_all_string_submatch_n(`\b(?:url|baseURL|uri|host|hostname)\s*:\s*([^,\n}]+)`, txt, -1)
	d := trim_space(m[1])
}

# Host fixed by a literal (scheme://host...) or by a configuration base.
_fixed(a) if regex.match(`^(?:f|r|b)?["'\x60]\s*(?:https?|ftp)://[^/"'\x60{$\s]`, a)

_fixed(a) if regex.match(`^\s*(?:[A-Z][A-Z0-9_]{2,}|(?:settings|config|conf|self\.(?:base_url|api_url|BASE_URL))(?:\.\w+)*)\b`, a)

_fixed(a) if regex.match(`^f?["'\x60]\$?\{\s*(?:[A-Z][A-Z0-9_]{2,}|settings\.|config\.|conf\.|process\.env\.)`, a)

_fixed(a) if regex.match(`^["'\x60][^"'\x60:]*["'\x60]`, a)

_names1(lines, i, src) := {v |
	some j in numbers.range(max([0, i - 20]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(src, prev)
	some v in _assigned(prev)
}

_assigned(line) := _first(line) | _destructured(line)

_first(line) := {v | v := helpers.assigned_first(line)}

_destructured(line) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	ps := split(trim_space(part), ":")
	v := trim_space(ps[count(ps) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

# One further hop: full = base + "/x", where base came from the request.
_names2(lines, i, n1) := {v |
	count(n1) > 0
	re := concat("", [`=\s*(?:f?["'\x60][^"'\x60]*["'\x60]\s*\+\s*)?(?:f?["'\x60](?:https?://)?\$?\{)?\b(?:`, concat("|", n1), `)\b`])
	some j in numbers.range(max([0, i - 20]), i - 1)
	regex.match(re, lines[j])
	v := helpers.assigned_first(lines[j])
}

_tainted_arg(a, src, _) if regex.match(src, a)

_tainted_arg(a, _, names) if {
	some v in names
	regex.match(concat("", [`\b`, v, `\b`]), a)
}

_guarded(lines, i) if {
	some j in numbers.range(max([0, i - 12]), i - 1)
	not helpers.is_comment_line(lines[j])
	not regex.match(`^\s*(?:async\s+)?(?:def|function|class)\s`, lines[j])
	regex.match(_guard, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_src(lang), content)
	sinks := _sinks(content, lang)
	regex.match(concat("", ["(?m)", sinks[0], "|", sinks[1]]), content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"[^"{}$]*"|'[^'{}$]*'`, `""`)
	regex.match(concat("|", sinks), code)
	some a in _url_args(lines, i, line, sinks)
	not _fixed(a)
	n1 := _names1(lines, i, _src(lang))
	names := n1 | _names2(lines, i, n1)
	_tainted_arg(a, _src(lang), names)
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Server-side request to a URL taken from the incoming request (SSRF): a client can reach internal services or cloud metadata. Fix the host, or check the URL's host against an allow-list before calling",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
