package vulnetix.rules.vnx_cs_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-008",
	"name": "C# SSRF: request data chooses the host of an HttpClient, WebClient or WebRequest call",
	"description": "An outbound HTTP request is sent to a URL whose scheme and host an HTTP client controls, so the server can be made to call internal services or cloud metadata endpoints (SSRF). Reported: the URL argument of an HttpClient method (GetAsync, GetStringAsync, GetByteArrayAsync, GetStreamAsync, GetFromJsonAsync, PostAsync, PutAsync, PatchAsync, DeleteAsync and the AsJson variants) or a WebClient method (DownloadString/Data/File, OpenRead/OpenWrite, UploadString/Data/File/Values and their Async/TaskAsync forms) on a receiver declared as HttpClient/WebClient/RestClient, created with new or IHttpClientFactory.CreateClient, an inline new WebClient()/HttpClient(), or chained onto factory.CreateClient(...); WebRequest/HttpWebRequest.Create/CreateHttp; new HttpRequestMessage(method, url); new RestClient(url); BaseAddress/RequestUri assignments; and, in a file using Flurl, a Flurl call chain (WithHeader, GetStringAsync, PostJsonAsync...) whose receiver is the URL string itself, or new Url/FlurlRequest/FlurlClient(url), when the URL begins with request data: Request.Query/QueryString/Form/Params/Cookies/Headers/RouteValues, Request[...], RouteData.Values, a WebForms TextBox .Text, a string parameter of a controller action, a [FromQuery]/[FromRoute]/[FromForm]/[FromHeader] parameter or a minimal-API lambda parameter, used inline, wrapped in new Uri(...), after only a scheme (\"http://\" + host, $\"https://{host}/...\"), or through a variable assigned that way up to 15 lines above. Not reported: request data that only fills the path or query of a URL whose host is a literal (\"/api/items/\" + id, $\"https://api.example.com/search?q={q}\"), URLs from configuration, URLs checked against a host allowlist (AllowedHosts.Contains(uri.Host)), an IsAllowed/IsValid/IsTrusted method or Regex.IsMatch in the 15 lines above, non-HTTP receivers such as IDistributedCache.GetAsync, parameters of non-controller methods (the caller is not followed), and the pattern in comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-008/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1090"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ssrf", "csharp"],
}

# ── Text helpers ─────────────────────────────────────────────────────────

# Plain string literals become "L", except a bare scheme ("http://") which
# becomes "" so that "http://" + host still reads as host-controlled.
# Interpolated strings keep their text and holes.
_code(line) := regex.replace(
	regex.replace(
		regex.replace(line, `(^|[^$@"])"(?i:(?:https?|ftp|wss?)://|//)"`, `${1}__SCHEME__`),
		`(^|[^$@"])"(?:\\.|[^"\\])+"`, `${1}"L"`,
	),
	`__SCHEME__`, `""`,
)

_ends_stmt(lines, j) if contains(lines[j], ";")

_ends_stmt(lines, j) if contains(lines[j], "{")

_stmt_end(lines, k) := e if {
	last := min([count(lines) - 1, k + 6])
	ends := [j | some j in numbers.range(k, last); _ends_stmt(lines, j)]
	e := min(array.concat([last], ends))
}

_stmt(lines, k) := _code(concat(" ", array.slice(lines, k, _stmt_end(lines, k) + 1)))

_word(name, text) if regex.match(concat("", [`\b`, name, `\b`]), text)

_arg_re := `^(?:[^(),;]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*`

_first_arg(rest) := regex.find_n(_arg_re, rest, 1)[0]

_second_arg(rest) := a if {
	first := _first_arg(rest)
	after := substring(rest, count(first), -1)
	startswith(after, ",")
	a := _first_arg(substring(after, 1, -1))
}

# ── Sinks ────────────────────────────────────────────────────────────────

_client_methods := `(?:GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|GetFromJsonAsync|PostAsync|PostAsJsonAsync|PutAsync|PutAsJsonAsync|PatchAsync|PatchAsJsonAsync|DeleteAsync|DeleteFromJsonAsync|DownloadString|DownloadStringAsync|DownloadStringTaskAsync|DownloadData|DownloadDataAsync|DownloadDataTaskAsync|DownloadFile|DownloadFileAsync|DownloadFileTaskAsync|OpenRead|OpenReadAsync|OpenReadTaskAsync|OpenWrite|OpenWriteAsync|UploadString|UploadStringAsync|UploadStringTaskAsync|UploadData|UploadDataAsync|UploadDataTaskAsync|UploadFile|UploadFileAsync|UploadValues|UploadValuesAsync)`

# Generic arguments (GetFromJsonAsync<List<Item>>) sit between name and call.
_method_call_re := concat("", [`\.\s*`, _client_methods, `\s*(?:<(?:[^<>()]|<[^<>()]*>)*>)?\s*\(`])

_receivers(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(?:HttpClient|WebClient|HttpMessageInvoker|RestClient)\??\s+([A-Za-z_]\w*)\b`, content, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:new\s+(?:System\.Net\.(?:Http\.)?)?(?:HttpClient|WebClient)\b|[\w.]+\.CreateClient\s*\()`, content, -1)
}

# The text after one sink match, with the remaining matches put back.
_rests(re, stmt) := [rest |
	ms := regex.find_n(re, stmt, -1)
	pieces := regex.split(re, stmt)
	some k, _ in ms
	rest := concat("", [concat("", [pieces[j], _ms_at(ms, j)]) |
		some j in numbers.range(k + 1, count(pieces) - 1)
	])
]

_ms_at(ms, j) := ms[j] if j < count(ms)

_ms_at(ms, j) := "" if j >= count(ms)

_url_args(stmt, recv) := {a |
	some n in recv
	re := concat("", [`(?:^|[^\w.])`, n, `\s*`, _method_call_re])
	some rest in _rests(re, stmt)
	a := _first_arg(rest)
} | {a |
	re := concat("", [`\bnew\s+(?:System\.Net\.(?:Http\.)?)?(?:WebClient|HttpClient)\s*\([^()]*\)\s*`, _method_call_re])
	some rest in _rests(re, stmt)
	a := _first_arg(rest)
} | {a |
	# factory.CreateClient("name").GetAsync(url)
	re := concat("", [`\.\s*CreateClient\s*\([^()]*\)\s*`, _method_call_re])
	some rest in _rests(re, stmt)
	a := _first_arg(rest)
} | {a |
	re := `\b(?:Http)?WebRequest\s*\.\s*(?:Create|CreateHttp|CreateDefault)\s*\(|\bnew\s+(?:RestSharp\.)?RestClient\s*\(`
	some rest in _rests(re, stmt)
	a := _first_arg(rest)
} | {a |
	re := `\bnew\s+(?:System\.Net\.Http\.)?HttpRequestMessage\s*\(`
	some rest in _rests(re, stmt)
	a := _second_arg(rest)
} | {a |
	re := `\b(?:BaseAddress|RequestUri)\s*=\s*`
	some rest in _rests(re, stmt)
	a := _first_arg(rest)
}

_sink_gate_re := concat("", [_method_call_re, `|WebRequest\s*\.\s*Create|HttpRequestMessage\s*\(|RestClient\s*\(|\b(?:BaseAddress|RequestUri)\s*=`])

# ── Sources ──────────────────────────────────────────────────────────────

_src_re := `\b[Rr]equest\s*(\.\s*(QueryString|Query|Form|Params|Cookies|Headers|RouteValues|ServerVariables|RawUrl|UrlReferrer)\b|\[)|\bRouteData\.Values\b|\b(txt|tb)[A-Z]\w*\.Text\b|\bTextBox\w*\.Text\b`

_is_controller(content) if regex.match(`class\s+\w+[^{]*:\s*[\w.]*(Controller|ControllerBase|PageModel)\b|\[ApiController\]`, content)

_inert_type := `^(int|long|short|byte|sbyte|uint|ulong|ushort|bool|Guid|DateTime|DateTimeOffset|TimeSpan|decimal|double|float|CancellationToken|HttpContext|HttpRequest|HttpResponse|HttpClient|IHttpClientFactory|HttpContent|object|EventArgs|\w+EventArgs)\??$`

_member_header(line) if regex.match(`^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|partial)\s+)+[\w<>\[\],.?\s]*?\b\w+\s*\(`, line)

_map_header(line) if regex.match(`\.Map(Get|Post|Put|Delete|Patch|Methods)?\s*\(`, line)

_param_names(text) := {p[2] |
	some raw in split(text, ",")
	p := regex.find_all_string_submatch_n(`^\s*(?:(?:ref|out|in|params|this)\s+)?([\w.]+(?:<[^>]*>)?(?:\[\])?\??)\s+([A-Za-z_]\w*)\s*(?:=.*)?$`, raw, 1)[0]
	not regex.match(_inert_type, p[1])
}

_header_params(lines, h) := plist if {
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 5])))
	stripped := regex.replace(joined, `\[[^\]]*\]`, "")
	m := regex.find_all_string_submatch_n(`\w+\s*\(([^()]*)\)`, stripped, 1)
	count(m) > 0
	plist := m[0][1]
}

_bound_params(lines, h) := {p[2] |
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 5])))
	some p in regex.find_all_string_submatch_n(`\[From(?:Query|Route|Form|Header)[^\]]*\]\s*([\w.<>\[\]?]+)\s+([A-Za-z_]\w*)`, joined, -1)
	not regex.match(_inert_type, p[1])
}

_lambda_params(lines, h) := {n |
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 3])))
	stripped := regex.replace(joined, `\[[^\]]*\]`, "")
	some m in regex.find_all_string_submatch_n(`\(([^()]*)\)\s*=>`, stripped, -1)
	some n in _param_names(m[1])
}

_nearest_header(lines, i) := h if {
	hs := [k | some k in numbers.range(max([0, i - 60]), i); _member_header(lines[k])]
	count(hs) > 0
	h := max(hs)
}

_ctl_params(lines, content, i) := ps if {
	_is_controller(content)
	h := _nearest_header(lines, i)
	regex.match(`^\s*(?:\[[^\]]*\]\s*)*public\b`, lines[h])
	ps := _param_names(_header_params(lines, h))
}

_bound_near(lines, i) := _bound_params(lines, _nearest_header(lines, i))

_map_params(lines, i) := ps if {
	hs := [k | some k in numbers.range(max([0, i - 15]), i); _map_header(lines[k])]
	count(hs) > 0
	ps := _lambda_params(lines, max(hs))
}

_params(lines, content, i) := {n | some n in _ctl_params(lines, content, i)} | {n | some n in _bound_near(lines, i)} | {n | some n in _map_params(lines, i)}

_direct(lines, content, i) := {v |
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	c := _code(l)
	regex.match(_src_re, c)
	not regex.match(_sink_gate_re, c)
	v := helpers.assigned_first(l)
} | _params(lines, content, i)

# ── Host control ─────────────────────────────────────────────────────────

# What precedes the value is at most a scheme (and a new Uri( wrapper).
_prefix_open(prefix) if {
	p := regex.replace(prefix, `new\s+(?:System\.)?Uri\s*\(|\((?:string|Uri)\)|\$@?"|@\$"|""|[\s+({]`, "")
	regex.match(`^(?i:(?:https?|ftp|wss?)://|//)?$`, p)
}

_host_ctrl(arg, _) if {
	regex.match(_src_re, arg)
	_prefix_open(regex.split(_src_re, arg)[0])
}

_host_ctrl(arg, names) if {
	some n in names
	re := concat("", [`\b`, n, `\b`])
	regex.match(re, arg)
	_prefix_open(regex.split(re, arg)[0])
}

_rhs(c) := substring(c, indexof(c, m) + count(m), -1) if {
	m := regex.find_n(`[^=!<>]=\s*`, c, 1)[0]
}

# One further assignment whose value is still host-controlled.
_tainted(lines, content, i) := t0 | {v |
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	c := _code(l)
	not regex.match(_sink_gate_re, c)
	v := helpers.assigned_first(l)
	not v in t0
	_host_ctrl(_rhs(c), t0)
} if {
	t0 := _direct(lines, content, i)
}

# ── Guards ───────────────────────────────────────────────────────────────

_guard_re := `(?i)\b(allow|white|safe|permit|trusted)\w*\.(Contains|Any)\s*\(|\bIs(Allowed|Trusted|Safe|Valid|Permitted)\w*\s*\(|\.Host\s*[!=]=|\.Host\b[^;\n]*\b(EndsWith|Equals|StartsWith)\b|\bRegex\.IsMatch\s*\(|\.IsMatch\s*\(`

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 15, 0))

# ── Flurl ────────────────────────────────────────────────────────────────
# Flurl sends from a string or Url receiver: callbackUrl.GetStringAsync(),
# callbackUrl.WithHeader(...).PostJsonAsync(...), new Url(x).GetAsync().

_flurl_verbs := `(?:With\w+|AllowAnyHttpStatus|AllowHttpStatus|AppendPathSegments?|SetQueryParams?|(?:Get|Post|Put|Patch|Delete|Head|Options|Send)\w*Async|DownloadFileAsync)\b`

_flurl_sink(lines, content, i, code) if {
	some m in regex.find_all_string_submatch_n(`(?:\bawait|\breturn|[^=!<>]=)\s*([A-Za-z_]\w*)\s*(?:\.|$)`, code, -1)
	n := m[1]
	not n in {"new", "await", "this", "base", "null"}
	stmt := _stmt(lines, i)
	regex.match(concat("", [`(?:^|[^\w.])`, n, `\s*\.\s*`, _flurl_verbs]), stmt)
	n in _tainted(lines, content, i)
}

_flurl_sink(lines, content, i, code) if {
	contains(code, "new")
	some rest in _rests(`\bnew\s+(?:Flurl\.(?:Http\.)?)?(?:Url|FlurlRequest|FlurlClient)\s*\(`, _stmt(lines, i))
	_host_ctrl(trim_space(_first_arg(rest)), _tainted(lines, content, i))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	contains(content, "Flurl")
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`\bawait\b|\breturn\b|=|\bnew\s+(?:Url|Flurl)`, line)
	code := _code(line)
	_flurl_sink(lines, content, i, code)
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP request data decides where this server sends an outbound request (SSRF): it can reach internal services and cloud metadata endpoints. Parse the URL with Uri.TryCreate and allow only known hosts and schemes, or keep the host fixed and pass the value only as an escaped path or query component",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	regex.match(concat("", [`(?m)`, _sink_gate_re]), content)
	recv := _receivers(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_sink_gate_re, _code(line))
	stmt := _stmt(lines, i)
	some arg in _url_args(stmt, recv)
	_host_ctrl(trim_space(arg), _tainted(lines, content, i))
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP request data decides where this server sends an outbound request (SSRF): it can reach internal services and cloud metadata endpoints. Parse the URL with Uri.TryCreate and allow only known hosts and schemes, or keep the host fixed and pass the value only as an escaped path or query component",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
