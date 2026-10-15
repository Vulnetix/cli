# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_183

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-183",
	"name": "Permissive List of Allowed Inputs",
	"description": "A trust decision on a URL, host, origin, referer or redirect target that accepts more than it names: a suffix check against a domain without a leading dot (origin.endsWith(\"example.com\") accepts evilexample.com), a prefix check against a scheme+host without a trailing slash (url.startsWith(\"https://example.com\") accepts https://example.com.evil.net), a substring check for a domain (contains/includes/indexOf/'in'/strings.Contains/strpos/str_contains), or any of these against an allow-list entry held in a variable named allowed/trusted/whitelist/safe (url.includes(allowedUrl) in a loop); the subject may be a parsed host or header getter (URI.create(u).getHost(), urlparse(u).netloc, req.get('origin'), r.Header.Get(\"Referer\"), $_SERVER['HTTP_REFERER']) or a local derived from a URL-named value in one or two assignments (decoded = URLDecoder.decode(target); lower = decoded.toLowerCase()); a regular-expression allow-list (/.../.test(origin), origin.match(/.../), re.match/re.search) for a domain with an unescaped '.', no '$' and no '/' after the host, no start anchor, or a wildcard before the domain; and an allow-list variable (ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS, allowedOrigins...) whose first entry is the wildcard \"*\". Covers Java, JavaScript/TypeScript, Python, Go and PHP. Not reported: exact equality or set membership (ALLOWED.contains(origin), host in ALLOWED_HOSTS), a suffix with a leading dot, a prefix ending in '/', a regex anchored at both ends with escaped dots or ending the host with (?:/|$), re.fullmatch, checks on values (email addresses, file names) not named as a URL/host/origin, scheme-only or path prefixes (\"https://\", \"/api/\"), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-183/",
	"languages": ["java", "node", "python", "go", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [183],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["allowlist", "validation", "open-redirect", "cors", "cwe-183"],
}


_subject_re := `(?i)(?:url|uri|host|hostname|netloc|authority|origin|referr?er|domain|redirect|next|return|target|callback|cb|location|dest|destination|link|href|site)\w*$`

# Names that only ever hold a value about to be trusted.
_strong_subject_re := `(?i)(?:origin|referr?er|redirect|callback)\w*$`

# A weakly named subject (url, host) is a trust decision when a redirect, a
# CORS header or a trusted/allowed name is near it.
_trust_context_re := `(?i)redirect|Location|Access-Control-Allow|trust|allowed|allowlist|whitelist|is_?safe|internal|same_?(?:origin|site)`

# Every reported shape needs one of these words in the file: an allow-list
# name, a strongly named subject, or the trust context.
# A file can match only when it holds a quoted domain literal or passes an
# allow-list variable to a call (or tests one with 'in').
_tlds := ["com", "org", "net", "io", "dev", "app", "local", "co", "uk", "de", "fr", "nl", "jp", "cn", "ru", "in", "au", "ca", "us", "eu", "gov", "edu", "cloud", "ai", "me", "info", "biz", "internal", "site", "tech", "lu"]

_domain_ends := {concat("", [".", t, q]) | some t in _tlds; some q in ["\"", "'"]}

_allow_arg_words := ["(allow", "(Allow", "(ALLOW", "(trust", "(Trust", "(TRUST", "(white", "(White", "(WHITE", "(safe", "(Safe", "(SAFE", "(permit", "(Permit", ", allow", ", trust", ", white", ", safe", ", permit", "allowed in ", "trusted in "]

_gate_tokens := _domain_ends | {w | some w in _allow_arg_words}

# The gate tokens this file holds; a candidate line holds one of them.
_tokens_in(content) := {w | some w in _gate_tokens; contains(content, w)}

_ext_ok := {"py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "go", "php"}

_src[path] := content if {
	some path, content in input.file_contents
	parts := split(path, ".")
	_ext_ok[parts[count(parts) - 1]]
	not _bundle(path)
}

_trust_decision(lines, i, s) if regex.match(_strong_subject_re, _last(s))

_trust_decision(lines, i, _) if {
	some j in numbers.range(max([0, i - 6]), min([count(lines) - 1, i + 6]))
	regex.match(_trust_context_re, lines[j])
}

_allow_var_re := `(?i)^(?:allow|white|trust|safe|permit)\w*$`

_domain_re := `(?i)^["'](?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}["']$`

_kind("endsWith") := "suffix"

_kind("endswith") := "suffix"

_kind("HasSuffix") := "suffix"

_kind("str_ends_with") := "suffix"

_kind("startsWith") := "prefix"

_kind("startswith") := "prefix"

_kind("HasPrefix") := "prefix"

_kind("str_starts_with") := "prefix"

_kind(m) := "contains" if {
	{"includes", "contains", "indexOf", "Contains", "Index", "str_contains", "strpos", "stripos", "strstr", "in"}[m]
}

# [subject, method, argument]
_calls(line) := {[s, m, a] |
	some x in regex.find_all_string_submatch_n(`(\$?[A-Za-z_][\w.]*(?:\(\s*(?:["'][\w-]+["'])?\s*\))?)\s*\.\s*(endsWith|endswith|startsWith|startswith|includes|contains|indexOf)\s*\(\s*([^(),]+?)\s*[,)]`, line, -1)
	s := x[1]
	m := x[2]
	a := x[3]
} | {[s, m, a] |
	some x in regex.find_all_string_submatch_n(`\bstrings\.(HasSuffix|HasPrefix|Contains|Index)\s*\(\s*([A-Za-z_][\w.]*(?:\(\s*(?:"[\w-]+")?\s*\))?)\s*,\s*([^(),]+?)\s*\)`, line, -1)
	s := x[2]
	m := x[1]
	a := x[3]
} | {[s, m, a] |
	some x in regex.find_all_string_submatch_n(`\b(str_ends_with|str_starts_with|str_contains|strpos|stripos|strstr)\s*\(\s*(\$\w+(?:\s*\[\s*['"][\w-]+['"]\s*\])?)\s*,\s*([^(),]+?)\s*[,)]`, line, -1)
	s := x[2]
	m := x[1]
	a := x[3]
} | {[s, "in", a] |
	some x in regex.find_all_string_submatch_n(`("[^"\n]+"|'[^'\n]+'|\b[A-Za-z_]\w*)\s+in\s+([A-Za-z_][\w.]*)`, line, -1)
	s := x[2]
	a := x[1]
}

# The last member of the subject, with a getter's call or a header key folded
# in: getHost() is getHost, req.get('origin') is getorigin,
# $_SERVER['HTTP_REFERER'] is _SERVERHTTP_REFERER.
_last(s) := p if {
	parts := split(s, ".")
	p := regex.replace(parts[count(parts) - 1], `[^\w]`, "")
}

_subject_ok(_, _, s) if regex.match(_subject_re, _last(s))

# A plain local derived, in one or two assignments within eight lines, from a
# URL-named value: decoded = URLDecoder.decode(target); lower = decoded.toLowerCase().
_subject_ok(lines, i, s) if {
	not regex.match(_subject_re, _last(s))
	regex.match(`^[A-Za-z_]\w*$`, s)
	some r in _rhs_ids(lines, i, s)
	regex.match(_subject_re, r)
}

_subject_ok(lines, i, s) if {
	not regex.match(_subject_re, _last(s))
	regex.match(`^[A-Za-z_]\w*$`, s)
	some j in numbers.range(max([0, i - 8]), i - 1)
	some r in _assigned_ids(lines[j], s)
	not regex.match(_subject_re, r)
	some r2 in _rhs_ids(lines, j, r)
	regex.match(_subject_re, r2)
}

_rhs_ids(lines, i, s) := {r |
	some j in numbers.range(max([0, i - 8]), i - 1)
	some r in _assigned_ids(lines[j], s)
}

_assigned_ids(l, s) := {r |
	contains(l, s)
	some m in regex.find_all_string_submatch_n(concat("", [`\b`, s, `\s*:?=\s*([^=;][^;]*)`]), l, 1)
	some r in regex.find_n(`[A-Za-z_]\w*`, m[1], -1)
	not _rhs_noise[r]
}

_rhs_noise := {"toLowerCase", "toUpperCase", "lower", "upper", "trim", "strip", "String", "new", "decode", "URLDecoder", "StandardCharsets", "UTF_8"}

_domain(a) if {
	regex.match(_domain_re, a)
	not regex.match(`(?i)\.(?:ya?ml|json|js|ts|png|jpe?g|gif|svg|html?|xml|txt|md|tf|py|go|php|java|css|zip|gz|tar|sh|exe|pdf|csv|lock|toml|ini|conf|log)["']$`, a)
}

_permissive(kind, a, lines, i, s) if {
	kind != "suffix"
	_domain(a)
	_trust_decision(lines, i, s)
}

_permissive("suffix", a, lines, i, s) if {
	_domain(a)
	not regex.match(`^["']\.`, a)
	_trust_decision(lines, i, s)
}

_permissive(_, a, _, _, _) if regex.match(_allow_var_re, a)

_loop_header("in", line) if regex.match(`^\s*(?:async\s+)?for\s`, line)

_in_string(line, word) if {
	idx := indexof(line, word)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	_odd(pre)
}

_odd(pre) if count(regex.find_n(`"`, pre, -1)) % 2 == 1

_odd(pre) if count(regex.find_n(`'`, pre, -1)) % 2 == 1

_wildcard_re := `(?i)\b\w*(?:allow|white|trust|permit|safe)\w*\s*(?::\s*[\w\[\]<>, ]+)?\s*:?=\s*(?:new\s+)?(?:[\w.]+\s*(?:<[^>]*>)?\s*\(\s*[\[\{]?|\[\]\w+\{|[\[\{\(])\s*["']\*["']`

# Bundled third-party code (yarn plugins, minified and vendored copies).
_bundle(path) if contains(path, ".yarn/")

_bundle(path) if contains(path, ".min.")

_bundle(path) if contains(path, "node_modules/")

_has_token(line, toks) if {
	some w in toks
	contains(line, w)
}

_allow_word(s) if {
	some w in ["llow", "LLOW", "rust", "RUST", "hite", "HITE", "afe", "AFE", "ermit", "ERMIT"]
	contains(s, w)
}

_quoted_star(s) if contains(s, `"*"`)

_quoted_star(s) if contains(s, `'*'`)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains f if {
	some path, content in _src
	toks := _tokens_in(content)
	count(toks) > 0
	lines := split(content, "\n")
	some i, line in lines
	_has_token(line, toks)
	count(line) < 1000
	not helpers.is_comment_line(line)
	some c in _calls(line)
	_subject_ok(lines, i, c[0])
	not regex.match(`(?i)^(?:allow|white|trust|safe|permit)`, _last(c[0]))
	not _loop_header(c[1], line)
	_permissive(_kind(c[1]), c[2], lines, i, c[0])
	not _in_string(line, c[1])
	f := _finding(path, i, line, "Allow-list check accepts more than it names: a domain suffix without a leading dot, a scheme+host prefix without a trailing '/', or a substring match lets evilexample.com or example.com.evil.net through. Parse the URL and compare its host exactly, or against '.'+domain")
}

findings contains f if {
	some path, content in _src
	_quoted_star(content)
	_allow_word(content)
	lines := split(content, "\n")
	some i, line in lines
	_quoted_star(line)
	regex.match(_wildcard_re, line)
	not helpers.is_comment_line(line)
	f := _finding(path, i, line, "Allow-list contains the wildcard '*', which accepts every value; list the hosts or origins that are actually allowed")
}

# ---- Regular-expression allow-lists -------------------------------------
# [pattern, subject, anchored-at-start-by-the-API]
_regex_checks(line) := {[p, s, false] |
	some x in regex.find_all_string_submatch_n(`/((?:[^/\n\\]|\\.)+)/[a-z]*\.test\s*\(\s*(\$?[A-Za-z_][\w.]*(?:\(\s*(?:["'][\w-]+["'])?\s*\))?)\s*\)`, line, -1)
	p := x[1]
	s := x[2]
} | {[p, s, false] |
	some x in regex.find_all_string_submatch_n(`(\$?[A-Za-z_][\w.]*)\s*\.match\s*\(\s*/((?:[^/\n\\]|\\.)+)/[a-z]*\s*\)`, line, -1)
	p := x[2]
	s := x[1]
} | {[p, s, a] |
	some x in regex.find_all_string_submatch_n(`\bre\.(match|search)\s*\(\s*r?["']([^"'\n]+)["']\s*,\s*([A-Za-z_][\w.]*)`, line, -1)
	p := x[2]
	s := x[3]
	a := x[1] == "match"
}

_tld_alt := concat("|", _tlds)

_regex_domain(p) if regex.match(concat("", [`(?i)[a-z0-9-](?:\\\.|\.)(?:`, _tld_alt, `)\b`]), p)

# An unescaped '.' between two labels matches any character.
_regex_permissive(p, _) if regex.match(`(?i)[a-z0-9-]\.[a-z0-9]`, p)

# No end anchor and no '/' after the host: example.com.evil.net matches.
_regex_permissive(p, _) if {
	not contains(p, "$")
	not regex.match(concat("", [`(?i)(?:`, _tld_alt, `)(?:\\?/)`]), p)
}

# No start anchor before the first label: evilexample.com matches.
_regex_permissive(p, false) if regex.match(`(?i)^[a-z0-9]`, p)

# A wildcard before the domain accepts any host or path in front of it.
_regex_permissive(p, _) if regex.match(concat("", [`\.[*+][^$]*\\\.(?:`, _tld_alt, `)\b`]), p)

findings contains f if {
	some path, content in _src
	_has_regex_call(content)
	lines := split(content, "\n")
	some i, line in lines
	_has_regex_call(line)
	count(line) < 1000
	not helpers.is_comment_line(line)
	some c in _regex_checks(line)
	_regex_domain(c[0])
	regex.match(_subject_re, _last(c[1]))
	_trust_decision(lines, i, c[1])
	_regex_permissive(c[0], c[2])
	f := _finding(path, i, line, "Regular-expression allow-list accepts more than it names: an unescaped '.', a missing ^ or $ anchor, or a wildcard before the domain lets evilexample.com or example.com.evil.net match. Anchor both ends, escape every dot, and end the host with (?:/|$)")
}

_has_regex_call(s) if contains(s, ".test(")

_has_regex_call(s) if contains(s, ".match(/")

_has_regex_call(s) if contains(s, "re.match(")

_has_regex_call(s) if contains(s, "re.search(")
