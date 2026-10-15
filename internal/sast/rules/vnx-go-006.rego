package vulnetix.rules.vnx_go_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-006",
	"name": "Go server-side request forgery",
	"description": "The server opens an outbound connection to a destination whose host the requester chooses: the URL or address given to http.Get/Head/Post/PostForm, http.NewRequest/NewRequestWithContext, an HTTP client's Get/Head/Post/PostForm, resty R().Get/Post..., httputil.NewSingleHostReverseProxy, net.Dial/DialTimeout/tls.Dial, or a websocket dialer (gorilla DefaultDialer.Dial, x/net websocket.Dial) starts with a value read from the request (r.FormValue, r.URL.Query().Get, r.Form/PostForm/Header.Get, gin/echo/fiber query, form and path parameters, gorilla/mux Vars, chi URLParam, r.PathValue, or a field of a struct decoded from the request body with json.NewDecoder(r.Body).Decode, json.Unmarshal of bytes read with io.ReadAll(r.Body), ShouldBindJSON/Bind or BodyParser), directly, through url.Parse, or through a variable assigned from it in the 30 lines above; or the value follows a prefix that does not pin the host (\"http://\" + v, \"https://api.\" + v + \".example.com\", fmt.Sprintf(\"http://%s:%s/...\", v, ...)). Reaching http://169.254.169.254 or an internal service is then one request away. Not reported: a fixed scheme and host followed by a path (\"https://api.github.com/repos/\" + v), destinations from configuration or constants, a value checked in between (an allowlist lookup, a Host/Hostname comparison, IsPrivate/IsLoopback, strings.HasPrefix against anything more than a bare scheme, or a helper named validate/allow/safe/trusted), a file whose client dials through a guard that rejects private and loopback addresses, cache and database Get calls (redis, kv, sql), and the call inside a string literal or comment.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-006/",
	"languages": ["go"],
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

_request := `\b(?:r|req|request)\.(?:FormValue|PostFormValue)\(|\b(?:r|req|request)\.URL\.Query\(\)(?:\.Get\(|\[)|\b(?:r|req|request)\.(?:Form|PostForm|Header)(?:\.Get\(|\[)|\bmux\.Vars\(|\.PathValue\(|\bchi\.URLParam\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|GetQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam)\(`

# Names assigned straight from a request read (optionally trimmed or parsed
# with url.Parse, which checks syntax and nothing about the destination).
_direct := concat("", [`(?::=|=)\s*(?:(?:strings\.\w+|url\.Parse|url\.ParseRequestURI)\(\s*)*(?:`, _request, `)`])

# Struct variables filled from the request body.
_bind_res := [
	`\.Decode\(\s*&(\w+)\s*\)`,
	`\.(?:ShouldBind(?:JSON|XML|YAML|Query|Uri|With)?|Bind(?:JSON|XML|YAML|Query|Uri)?|BodyParser)\(\s*&(\w+)\s*\)`,
	`\b(?:json|xml|yaml)\.Unmarshal\(\s*\w+\s*,\s*&(\w+)\s*\)`,
]

_bound(lines, i) := {v |
	lo := max([0, i - 30])
	some j in numbers.range(lo, i - 1)
	l := lines[j]
	regex.match(`\.Decode\(|Bind|BodyParser\(|Unmarshal\(`, l)
	not helpers.is_comment_line(l)
	_body_bind(lines, lo, j, l)
	some re in _bind_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	v := m[1]
}

_body_bind(_, _, _, l) if regex.match(`\.Body\b.*\.Decode\(`, l)

_body_bind(_, _, _, l) if regex.match(`\.(?:ShouldBind|Bind|BodyParser)`, l)

# json.Unmarshal of bytes read from the request body a few lines up.
_body_bind(lines, lo, j, l) if {
	m := regex.find_all_string_submatch_n(`Unmarshal\(\s*(\w+)\s*,`, l, 1)
	count(m) > 0
	b := m[0][1]
	some k in numbers.range(lo, j - 1)
	regex.match(concat("", [`\b`, b, `\b[^=]*:?=\s*(?:io|ioutil)\.ReadAll\(\s*(?:\w+\.)?(?:r|req|request|Request)\.Body\b`]), lines[k])
}

_word(v) := concat("", [`\b`, v, `\b`])

# A literal that leaves the host open: scheme and part of a host with no
# path slash after it, or nothing at all.
_open_prefix := `^(?:"(?:https?:|wss?:|tcp:)?//[^/"]*"|\x60(?:https?:)?//[^/\x60]*\x60|"")\s*\+\s*`

# A format whose first verb sits in the host part.
_open_format := `^fmt\.Sprintf\(\s*["\x60](?:(?:https?|wss?|tcp)://)?[^/"\x60%]*%[sv]`

_leads(e, _) if regex.match(concat("", [`^(?:(?:url\.Parse|url\.ParseRequestURI)\(\s*)?(?:`, _request, `)`]), e)

_leads(e, names) if {
	some v in names
	regex.match(concat("", [`^`, v, `\b`]), e)
	not regex.match(concat("", [`^`, v, `\s*\(`]), e)
}

_attacker_start(e, names) if _leads(e, names)

_attacker_start(e, names) if {
	regex.match(_open_prefix, e)
	_leads(regex.replace(e, _open_prefix, ""), names)
}

_attacker_start(e, names) if {
	regex.match(_open_format, e)
	args := regex.replace(e, `^fmt\.Sprintf\(\s*(?:"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60)\s*,\s*`, "")
	_leads(trim_space(args), names)
}

# Request-derived names: direct reads and body-bound structs, then names
# built from one of those so that it still leads the string.
_names(lines, i) := t1 | t2 if {
	t1 := helpers.tainted_names(lines, i, 30, _direct) | _bound(lines, i)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 30]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)(?:\s*,\s*\w+)*\s*:?=\s*(.+)$`, l, 1)
		count(m) > 0
		v := m[0][1]
		not v in t1
		_attacker_start(trim_space(m[0][2]), t1)
	}
}

_validator := `(?i)allow|valid|white_?list|trusted|permit|safe|deny|block|is_?private|is_?internal|IsLoopback|IsPrivate|IsGlobalUnicast|\.Hostname\(\)\s*(?:!=|==)|\.Host\s*(?:!=|==)|HasPrefix|HasSuffix`

# The leading name, or a name derived from it, is checked between the
# source and the sink.
_checked(lines, i, e, names) if {
	some v in names
	regex.match(concat("", [`^`, v, `\b`]), e)
	lo := max([0, i - 30])
	derived := {d |
		some j in numbers.range(lo, i - 1)
		regex.match(_word(v), lines[j])
		d := helpers.assigned_first(lines[j])
	}
	watch := derived | {v}
	some k in numbers.range(lo, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_validator, l)
	some w in watch
	regex.match(_word(w), l)
	not _scheme_only(l)
}

# HasPrefix/HasSuffix against a bare scheme ("http://", "https") only
# normalises the URL; it says nothing about the host.
_scheme_only(l) if {
	args := [trim_space(m[1]) | some m in regex.find_all_string_submatch_n(`Has(?:Prefix|Suffix)\(\s*[\w.]+\s*,\s*([^)]*)\)`, l, -1)]
	count(args) > 0
	every a in args {
		regex.match(`^"(?:https?|wss?)?:?(?://)?"$`, a)
	}
	not regex.match(`(?i)allow|valid|white_?list|trusted|permit|safe|deny|block|is_?private|is_?internal|IsLoopback|IsPrivate|IsGlobalUnicast|\.Hostname\(\)\s*(?:!=|==)|\.Host\s*(?:!=|==)`, l)
}

# Every connection goes through a dialer that refuses internal addresses.
_guarded(content) if regex.match(`(?i)\bssrf\.|ssrf_?(?:guard|safe|dial|transport|client)|safe_?dial`, content)

_guarded(content) if {
	regex.match(`\bControl:\s*\w|DialContext:\s*\w`, content)
	regex.match(`\.IsPrivate\(\)|\.IsLoopback\(\)`, content)
}

_stmt(lines, i, line) := line if not regex.match(`[(,]\s*$`, line)

_stmt(lines, i, line) := s if {
	regex.match(`[(,]\s*$`, line)
	last := min([count(lines) - 1, i + 4])
	s := concat(" ", [trim_space(lines[k]) | some k in numbers.range(i, last)])
}

_first_arg(s) := trim_space(regex.replace(s, `^\s*((?:"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60|\((?:[^()"]|"(?:[^"\\]|\\.)*"|\([^()]*\))*\)|[^,()"\x60])*).*$`, "$1"))

_skip_args(s, 0) := s

_skip_args(s, 1) := regex.replace(s, `^\s*[^,]+,\s*`, "")

_skip_args(s, 2) := regex.replace(s, `^\s*[^,]+,\s*[^,]+,\s*`, "")

# Sink pattern -> how many arguments precede the destination.
_sinks := {
	`\bhttp\.(?:Get|Head|Post|PostForm)\(`: 0,
	`\bhttp\.NewRequest\(`: 1,
	`\bhttp\.NewRequestWithContext\(`: 2,
	`\b(?:\w*[Hh]ttp\w*|\w*[Cc]lient\w*|hc|cl)\.(?:Get|Head|Post|PostForm)\(`: 0,
	`\.R\(\)\.(?:Get|Post|Put|Patch|Delete|Head)\(`: 0,
	`\bhttputil\.NewSingleHostReverseProxy\(`: 0,
	`\b(?:net|tls)\.(?:Dial|DialTimeout)\(`: 1,
	`\b\w*[Dd]ialer\w*\.DialContext\(`: 2,
	`\bwebsocket\.(?:\w*Dialer\.Dial|Dial)\(`: 0,
	`\bwebsocket\.\w*Dialer\.DialContext\(`: 1,
}

_not_http_client(stmt) if regex.match(`(?i)\b\w*(?:redis|cache|kv|etcd|db|sql|mongo|s3|dynamo|consul|vault|memcache|bolt|badger|store|grpc)\w*\.(?:Get|Head|Post)\(`, stmt)

_dests(stmt) := {e |
	some re, n in _sinks
	parts := regex.split(re, stmt)
	count(parts) > 1
	_code_prefix(parts[0])
	not _cache_call(re, stmt)
	e := _first_arg(_skip_args(parts[1], n))
}

_cache_call(re, stmt) if {
	contains(re, "Client")
	_not_http_client(stmt)
}

# The sink starts outside a string literal.
_code_prefix(prefix) if {
	p := regex.replace(prefix, `\\.`, "")
	not contains(p, "`")
	count(regex.find_all_string_submatch_n(`"`, p, -1)) % 2 == 0
}

_hint := `\b(?:http|httputil|net|tls)\.|\.(?:Get|Head|Post|PostForm|DialContext)\(`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(_hint, content)
	regex.match(concat("|", [_request, `\.Decode\(|Bind\w*\(|BodyParser\(|Unmarshal\(`]), content)
	not _guarded(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:Get|Head|Post|PostForm|NewRequest|NewRequestWithContext|NewSingleHostReverseProxy|Dial|DialTimeout|DialContext|Put|Patch|Delete)\(`, line)
	not helpers.is_comment_line(line)
	stmt := _stmt(lines, i, line)
	dests := _dests(stmt)
	count(dests) > 0
	names := _names(lines, i)
	some e in dests
	_attacker_start(e, names)
	not _checked(lines, i, e, names)
	finding := {
		"rule_id": metadata.id,
		"message": "Outbound request destination is taken from the HTTP request (SSRF); resolve the host and allow only expected destinations, refusing private, loopback and link-local addresses",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
