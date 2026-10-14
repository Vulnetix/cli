package vulnetix.rules.vnx_node_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-008",
	"name": "Node.js open redirect",
	"description": "A redirect whose target begins with request-controlled data: res/response.redirect([status,] url) (Express), ctx.redirect (Koa), reply.redirect (Fastify), h.redirect (hapi), res.location(url), a Location header set with res.writeHead(30x, { Location }) or res.setHeader/set/header('Location', url), and in browser code an assignment to window.location/location.href or location.assign/replace(url). The target is reported when it starts with req.query/params/body/cookies/headers, req.param(), ctx.query/params/request.query/body, request.query/params/body/payload, URLSearchParams(...).get() or location.search/hash, directly, as the first ${...} of a template literal, or through a variable assigned from one in the previous 15 lines (two hops for a URLSearchParams object). Not reported: constant targets, a path prefix followed by user data ('/users/' + id, `/pets/${id}`), which stays on the same site, Referer-based 'back' redirects, environment-derived targets, and a redirect preceded within 10 lines by an allow-list, origin/host comparison, startsWith('/') or validation check, test code (an open redirect in a test server is not reachable), plus comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-008/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1566"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["open-redirect", "web", "phishing"],
}

_is_js(path) if regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$`, path)

_file_gate := `redirect|Location|location`

_sinks := [
	`(?:^|[^\w$.])(?:res|response|reply|ctx|h)\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?(.*)$`,
	`(?:^|[^\w$.])(?:res|response)\.location\s*\(\s*(.*)$`,
	`\.writeHead\s*\(\s*30\d\s*,\s*\{\s*['"]?Location['"]?\s*:\s*(.*)$`,
	`\.(?:setHeader|set|header)\s*\(\s*['"]Location['"]\s*,\s*(.*)$`,
	`(?:^|[^\w$.])(?:(?:window|document|top|self)\.)?location(?:\.href)?\s*=\s*([^=].*)$`,
	`(?:^|[^\w$.])(?:window\.)?location\.(?:assign|replace)\s*\(\s*(.*)$`,
]

_src := `(?:req\.(?:query|params|body|cookies|headers|param\s*\()|request\.(?:query|params|body|payload)|ctx\.(?:query|params|request\.(?:query|body))|new\s+URLSearchParams\s*\(|(?:\w+\.)?searchParams\.get\s*\(|(?:(?:window|document)\.)?location\.(?:search|hash))`

_starts_with_src := concat("", [`^\s*(?:\(\s*)*(?:`, _src, `|\x60\$\{\s*`, _src, `)`])

# String literals collapse to "" so a sink spelled inside one disappears.
_strip(line) := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, `""`)

_guard_re := `(?i)allow|whitelist|safelist|trusted|issafe|isvalid|validat|isrelative|islocal|sameorigin|\.origin\b|\.host(?:name)?\s*[!=]==|startsWith\s*\(\s*['"]/`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	regex.match(_file_gate, content)
	regex.match(_src, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`redirect|[Ll]ocation`, line)
	count(line) <= 400
	not helpers.is_comment_line(line)
	s := _strip(line)
	some re in _sinks
	_sink_in_code(re, s)
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	target := m[0][1]
	not regex.match(`^\s*req\.(?:headers\s*(?:\.|\[\s*['"])|get\s*\(\s*['"]|header\s*\(\s*['"])refer`, target)
	_tainted(lines, i, target)
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Redirect target is taken from the request; an attacker can send users to any site. Redirect only to relative paths or to an allow-list of trusted origins",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_tainted(_, _, target) if regex.match(_starts_with_src, target)

_tainted(lines, i, target) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$]*)\s*(?:[,);|}]|\bas\b|$)`, target, 1)
	count(m) > 0
	m[0][1] in _tainted_names(lines, i)
}

# Names assigned, within 15 lines above, a value that starts with a request
# source; then names assigned from <tainted>.get(...) of those.
_tainted_names(lines, i) := t1 | t2 if {
	start := max([0, i - 15])
	assigns := [[n, rhs] |
		some j in numbers.range(start, i - 1)
		i > 0
		l := lines[j]
		not helpers.is_comment_line(l)
		a := regex.find_all_string_submatch_n(`^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*([^=].*)$`, l, 1)
		count(a) > 0
		n := a[0][1]
		rhs := a[0][2]
	]
	t1 := {a[0] | some a in assigns; regex.match(_starts_with_src, a[1])}
	t2 := {a[0] |
		some a in assigns
		some t in t1
		regex.match(concat("", [`^\s*`, t, `\.get\s*\(`]), a[1])
	}
}

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 10, 0))

# The sink is code, not text inside a string literal. The header sinks name
# "Location" in a literal, so they are checked on the raw line.
_sink_in_code(re, s) if regex.match(re, s)

_sink_in_code(re, _) if contains(re, "Location")
