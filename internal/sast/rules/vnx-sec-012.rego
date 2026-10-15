package vulnetix.rules.vnx_sec_012

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SEC-012",
	"name": "CORS wildcard or origin reflection",
	"description": "A server answers cross-origin requests from any website. Reported: the Access-Control-Allow-Origin response header set to the request's own Origin header (req.headers.origin, req.get('origin'), r.Header.Get(\"Origin\"), request.getHeader(\"Origin\"), request.META['HTTP_ORIGIN'], $_SERVER['HTTP_ORIGIN'], nginx $http_origin), directly or through a variable assigned from it a few lines above, with no allowlist check (includes/has/in_array/in/==, allowed[...]) on the origin in between; the header set to '*' (setHeader/header/set, Header().Set, response[...] =, headers[...] =, header(\"Access-Control-Allow-Origin: *\"), nginx add_header, Apache Header set, the ingress-nginx cors-allow-origin annotation); and CORS middleware configured for every origin: Express cors() with no options, origin: true/'*' or an origin callback that always answers cb(null, true), AWS CDK allowOrigins: Cors.ALL_ORIGINS, AWS SAM AllowOrigin: \"'*'\", FastAPI/Starlette allow_origins=[\"*\"] or allow_origin_regex=\".*\", Flask-CORS CORS(app) without origins or origins='*', django-cors-headers CORS_ALLOW_ALL_ORIGINS/CORS_ORIGIN_ALLOW_ALL = True, gin AllowAllOrigins: true, rs/cors AllowedOrigins []string{\"*\"} or an AllowOriginFunc that returns true, Spring allowedOrigins(\"*\")/allowedOriginPatterns(\"*\")/addAllowedOrigin(\"*\") and @CrossOrigin without origins or with origins \"*\" (also when its arguments span lines), Kotlin allowedOriginPatterns = listOf(\"*\"), Spring Cloud Gateway YAML allowedOrigins: \"*\" (or a list holding \"*\") and Boot properties cors.allowed-origins=*, ASP.NET Core AllowAnyOrigin(), SetIsOriginAllowed(_ => true) and WithOrigins(\"*\"), Laravel 'allowed_origins' => ['*'] and rack-cors origins '*'. Not reported: a wildcard whose configuration explicitly disables credentials nearby (allow_credentials=False, credentials: false), specific origins, an origin variable that is checked against an allowlist, the header set by client code (fetch/axios request headers), assertions and comparisons, test files, comments and documentation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-012/",
	"languages": [],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [942],
	"capec": ["CAPEC-111"],
	"attack_technique": ["T1189"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["cors", "misconfiguration", "web"],
}

_ext_re := `(?i)(\.(js|jsx|mjs|cjs|ts|tsx|py|go|java|kt|kts|cs|php|rb|conf|ya?ml|json|properties)|(^|/)\.htaccess)$`

# Every reported shape names one of these (case-insensitively).
_gate_words := ["access-control-allow-origin", "cors", "anyorigin", "originallowed", "alloworigin", "allow_origin", "allowedorigin", "crossorigin", "origins"]

_gate(content) if {
	lc := lower(content)
	some w in _gate_words
	contains(lc, w)
}

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)\.min\.js$|(^|/)(node_modules|vendor)/`, path)

_skip(path) if regex.match(`(^|/)([A-Za-z]+Tests?|[A-Za-z.]+\.Tests?)/`, path)

# ── The request's Origin header ─────────────────────────────────────────
_origin_src := `(?i)(headers?(\.get)?\s*[\[(.]\s*["']?origin\b|getheader\(\s*["']origin["']|\bheader\(\s*["']origin["']|\bget\(\s*["']origin["']|http_origin\b|request\.origin\b)`

# An allowlist decision about the origin.
_guard_re := `(?i)(\b(includes|indexof|has|contains|containskey|in_array|array_key_exists|matches|match|test|isallowed\w*|isvalid\w*|valid\w*)\s*\(|==|!=|\bin\s+[A-Za-z_][\w.]*\s*:|\b(allowed|trusted|whitelist|allowlist)\w*\s*\[|\bif\s*\(?\s*!?\s*\w*(allowed|trusted|whitelist|allowlist))`

# Where the header value starts, in each way of setting it.
_sink_res := [
	`(?i)access-control-allow-origin["']\s*(?:,|=>|:|\]\s*=)\s*(.*)$`,
	`(?i)access-control-allow-origin:\s*(?:["']\s*(?:\.|\+)\s*)?(.*)$`,
	`(?i)^\s*(?:add_header|more_set_headers|header\s+(?:always\s+)?(?:set|add|append|merge))\s+["']?access-control-allow-origin["']?:?\s+(.*)$`,
]

_sink_value(line) := v if {
	some re in _sink_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	v := m[0][1]
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:var|let|const|final|my|val|auto)\s+|[A-Za-z_][\w<>\[\]]*\s+)?(\$?[A-Za-z_]\w*)\s*(?::=|=)[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_ref_re(v) := concat("", [`(^|[^\w$])`, replace(v, "$", `\$`), `\b`])

# Variables assigned from the Origin header in the 10 lines above i.
_origin_vars(lines, i) := {[j, v] |
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(_origin_src, lines[j])
	v := _assigned(lines[j])
}

_reflects(lines, i, line) if {
	val := _sink_value(line)
	regex.match(_origin_src, val)
	not regex.match(_guard_re, val)
	not _guarded(lines, i, "origin")
}

_reflects(lines, i, line) if {
	val := _sink_value(line)
	not regex.match(_origin_src, val)
	some pair in _origin_vars(lines, i)
	v := pair[1]
	regex.match(_ref_re(v), val)
	not regex.match(_guard_re, val)
	not _guarded(lines, i, v)
}

# A line above the sink that tests the origin against an allowlist.
_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_guard_re, l)
	regex.match(concat("", [`(?i)`, _ref_re(v), `|origin`]), l)
	not regex.match(`(?i)access-control-allow-origin`, l)
}

# ── Wildcard ────────────────────────────────────────────────────────────
_wild_header(line) if regex.match(`(?i)access-control-allow-origin["']\s*(?:,|=>|\]\s*=)\s*["']\*["']`, line)

_wild_header(line) if regex.match(`(?i)["']access-control-allow-origin:\s*\*\s*["'\\]`, line)

_wild_header(line) if regex.match(`(?i)^\s*(?:add_header|more_set_headers|header\s+(?:always\s+)?(?:set|add|append|merge))\s+["']?access-control-allow-origin["']?:?\s+["']?\*`, line)

_wild_header(line) if regex.match(`(?i)cors-allow-origin["']?\s*:\s*["']?\*["']?\s*$`, line)

# Object / dict key form: also how client code wrongly sends the header
# with a request, so it is reported only away from a client call.
_wild_key(line) if regex.match(`(?i)access-control-allow-origin["']\s*:\s*["']\*["']`, line)

_client_re := `(?i)\bfetch\(|axios|\$\.ajax|xmlhttprequest|\brequests\.(get|post|put|patch|delete|request)\(|httpclient|\bgot\(|superagent|\bhttp\.(get|request)\(|\.(get|post|put|patch)\(\s*["'\x60]https?:`

_lang_wild(path, _, _, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)
	regex.match(`\bcors\(\s*\)`, line)
	not regex.match(`(?i)\bcors\(\s*\)\s*\.`, line)
}

_lang_wild(path, lines, i, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)
	regex.match(`(?:^|[\s{,])origin\s*:\s*(?:true\b|["']\*["'])`, line)
	regex.match(`(?i)\bcors\b`, helpers.code_window(lines, i, 6, 0))
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".py")
	regex.match(`\b(allow_origins|origins)\s*=\s*(?:["']\*["']|[\[(]\s*["']\*["']\s*,?\s*[\])])`, line)
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".py")
	regex.match(`\bCORS\(\s*\w+\s*(?:,\s*(?:supports_credentials|send_wildcard|max_age|methods|allow_headers|expose_headers)\s*=\s*[^,()]+\s*)*\)`, line)
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".py")
	regex.match(`^\s*CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True\b`, line)
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".go")
	regex.match(`\bAllowAllOrigins\s*:\s*true\b|\bAllow(?:ed)?Origins\s*:\s*\[\]string\{\s*"\*"\s*\}|\bcors\.AllowAll\(\)|\bAllowedOrigins\(\s*\[\]string\{\s*"\*"\s*\}\s*\)`, line)
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".go")
	regex.match(`\bAllowOriginFunc\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true\s*\}`, line)
}

_lang_wild(path, lines, i, line) if {
	endswith(path, ".go")
	regex.match(`\bAllowOriginFunc\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*$`, line)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*return\s+true\s*$`, lines[j])
}

_lang_wild(path, _, _, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	regex.match(`\.allowedOrigin(?:Pattern)?s\(\s*"\*"\s*\)|\baddAllowedOrigin(?:Pattern)?\(\s*"\*"\s*\)|\bsetAllowedOrigin(?:Pattern)?s\(\s*(?:List\.of|Arrays\.asList|Collections\.singletonList|listOf|mutableListOf)\(\s*"\*"\s*\)\s*\)`, line)
}

_lang_wild(path, _, _, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	m := regex.find_all_string_submatch_n(`^\s*@CrossOrigin\s*(?:\((.*)\))?\s*$`, line, 1)
	count(m) > 0
	_cross_origin_any(m[0][1])
}

_cross_origin_any(args) if {
	not regex.match(`(?i)origin|value|^\s*["{]`, args)
}

_cross_origin_any(args) if regex.match(`^\s*\{?\s*"\*"|\b(?:origins|value)\s*=\s*\{?\s*"\*"`, args)

# @CrossOrigin( with its arguments on the following lines.
_lang_wild(path, lines, i, line) if {
	regex.match(`\.(java|kt|kts)$`, path)
	regex.match(`^\s*@CrossOrigin\s*\(\s*$`, line)
	args := concat(" ", array.slice(lines, i + 1, i + 6))
	regex.match(`^[^)]*?(?:^\s*\{?\s*"\*"|\b(?:origins|value)\s*=\s*\{?\s*"\*")`, args)
}

# Kotlin property syntax on Spring's CorsConfiguration.
_lang_wild(path, _, _, line) if {
	regex.match(`\.(kt|kts)$`, path)
	regex.match(`\ballowedOrigin(?:Pattern)?s\s*=\s*(?:listOf|mutableListOf|arrayListOf)\(\s*"\*"\s*\)`, line)
}

# An origin callback that accepts every origin: cors({ origin: (o, cb) => cb(null, true) }).
_lang_wild(path, lines, i, line) if {
	regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)
	regex.match(`(?:^|[\s{,])origin\s*:\s*(?:async\s+)?(?:\([^)]*\)\s*=>|function\s*\w*\s*\([^)]*\))\s*\{?\s*(?:return\s+)?\w+\(\s*null\s*,\s*true\s*\)`, line)
	regex.match(`(?i)\bcors\b`, helpers.code_window(lines, i, 6, 0))
}

# AWS CDK: allowOrigins: Cors.ALL_ORIGINS or ['*'].
_lang_wild(path, _, _, line) if {
	regex.match(`\.(js|mjs|cjs|ts)$`, path)
	regex.match(`\ballowOrigins\s*:\s*(?:\[\s*["']\*["']\s*\]|(?:\w+\.)?Cors\.ALL_ORIGINS\b)`, line)
}

# Starlette/FastAPI allow_origin_regex that accepts anything.
_lang_wild(path, _, _, line) if {
	endswith(path, ".py")
	regex.match(`\ballow_origin_regex\s*=\s*r?["']\^?(?:https\??://)?\.[*+]\$?["']`, line)
}

# Spring Cloud Gateway / Boot YAML: allowedOrigins: "*" or a list holding "*".
_lang_wild(path, _, _, line) if {
	regex.match(`\.ya?ml$`, path)
	regex.match(`^\s*allowed-?[Oo]rigin(?:-?[Pp]attern)?s\s*:\s*\[?\s*["']?\*["']?\s*\]?\s*$`, line)
}

_lang_wild(path, lines, i, line) if {
	regex.match(`\.ya?ml$`, path)
	regex.match(`^\s*allowed-?[Oo]rigin(?:-?[Pp]attern)?s\s*:\s*$`, line)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*-\s*["']?\*["']?\s*$`, lines[j])
}

# AWS SAM / API Gateway: AllowOrigin: "'*'".
_lang_wild(path, _, _, line) if {
	regex.match(`\.(ya?ml|json)$`, path)
	regex.match(`^\s*["']?AllowOrigin["']?\s*:\s*["']'\*'["']`, line)
}

# Spring Boot properties: ...cors.allowed-origins=*.
_lang_wild(path, _, _, line) if {
	endswith(path, ".properties")
	regex.match(`(?i)cors\.allowed-?origin(?:-?patterns?)?s?\s*[=:]\s*\*\s*$`, line)
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".cs")
	regex.match(`\.AllowAnyOrigin\(\s*\)|\.SetIsOriginAllowed\(\s*\(?\s*\w*\s*\)?\s*=>\s*true\s*\)|\.WithOrigins\(\s*"\*"\s*\)`, line)
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".php")
	regex.match(`["']allowed_origins["']\s*=>\s*\[\s*["']\*["']\s*,?\s*\]`, line)
}

_lang_wild(path, _, _, line) if {
	endswith(path, ".rb")
	regex.match(`^\s*origins\s*\(?\s*["']\*["']`, line)
}

_creds_off_re := `(?i)(allow_?credentials|supports_credentials|credentials)["']?\s*(?:[:=]|=>)\s*false\b|allowcredentials\(\s*false\s*\)`

_creds_off(lines, i) if regex.match(_creds_off_re, helpers.code_window(lines, i, 12, 12))

_assertion(line) if regex.match(`(?i)\b(assert\w*|expect|should|verify)\b\s*[(.]|(==|!=)=?\s*["']\*["']|["']\*["']\s*(==|!=)`, line)

_kind(path, lines, i, line) := "reflect" if {
	_reflects(lines, i, line)
}

_kind(path, lines, i, line) := "wild" if {
	not _reflects(lines, i, line)
	_wild_header(line)
	not _creds_off(lines, i)
}

_kind(path, lines, i, line) := "wild" if {
	not _reflects(lines, i, line)
	not _wild_header(line)
	_wild_key(line)
	not regex.match(_client_re, helpers.code_window(lines, i, 8, 2))
	not _creds_off(lines, i)
}

_kind(path, lines, i, line) := "wild" if {
	not _reflects(lines, i, line)
	not _wild_header(line)
	not _wild_key(line)
	_lang_wild(path, lines, i, line)
	not _creds_off(lines, i)
}

_message := {
	"reflect": "Access-Control-Allow-Origin echoes the request's Origin header without an allowlist check; any website can read this response (with the user's cookies if credentials are allowed). Compare the origin against a fixed list of trusted origins first",
	"wild": "CORS allows every origin; restrict Access-Control-Allow-Origin to the specific trusted origins that need cross-origin access",
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_ext_re, path)
	_gate(content)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)origin|cors`, line)
	not helpers.is_comment_line(line)
	not _assertion(line)
	k := _kind(path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message[k],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
