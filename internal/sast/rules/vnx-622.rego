# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_622

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-622",
	"name": "Client-supplied JSONP callback name written into the response unvalidated",
	"description": "CWE-622 (unvalidated arguments to a function hook) has no general static signature in application JavaScript, so this rule reports its most concrete server-side form: a JSONP endpoint that takes the name of the function to call from the request (req/request/ctx .query/.params/.body .callback, .jsonp, .cb or .jsoncallback, url.parse(req.url, true).query.callback, searchParams.get('callback'), or a destructured const { callback } = req.query) and writes it into a script response as name + '(' or `${name}(` through res.send/write/end, ctx.body or reply.send, inline, through a variable assigned a few lines above, or into a body string that is sent within the next six lines. An unvalidated name lets the caller run any script in the page that loads the endpoint (reflected XSS, Rosetta-Flash-style content sniffing). Not reported: res.jsonp() (Express restricts the callback charset), a name read through a call named like a sanitiser or validator (sanitizeCallback(...)), sanitised with .replace(), checked against a regular expression, looked up in an allow-list (.has/.includes/.indexOf) or compared with a constant between the read and the write, a constant callback name, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-622/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [622],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["callback-validation", "jsonp", "cwe-622"],
}

_exts := {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}



_strip_strings(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

_has_ext(path) if {
	some ext in _exts
	endswith(path, ext)
}

_message := "The JSONP callback name comes from the request and is written into the script response unvalidated, so the caller chooses what code runs. Use res.jsonp(), or allow only /^[A-Za-z_$][\\w$.]*$/"

_key := `(callback|jsonp|cb|jsoncallback)`

_source := concat("", [
	`(\b(req|request|ctx)\.(query|params|body|request\.query)|\.query(\(\))?)(\.`, _key, `\b|\[\s*['"]`, _key, `['"]\s*\])`,
	`|searchParams\.get\(\s*['"]`, _key, `['"]`,
])

_sink := `(\bres\.(send|write|end)\s*\(|\.send\s*\(|\bctx\.body\s*=|\breply\.send\s*\(|\bresponse\.(send|write|end)\s*\()`

# A call named like a sanitiser or validator wrapping the read.
_sanitiser_call := `(?i)(saniti[sz]e|valid|safe|clean|escape|allow|whitelist)\w*\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path)
	regex.match(`(?i)callback|jsonp|\bcb\b`, content)
	regex.match(`\b(req|request|ctx)\.`, content)
	regex.match(_sink, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\+\s*['"]\(|\}\(`, line)
	not helpers.is_comment_line(line)
	not contains(line, ".jsonp(")
	_unvalidated_call(lines, i, line)
	_sink_near(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The script is written on this line, or built here and sent a few lines below.
_sink_near(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 6]))
	regex.match(_sink, lines[k])
}

# res.send(req.query.callback + '(' + ...) / res.send(`${req.query.callback}(...)`)
_unvalidated_call(_, _, line) if {
	regex.match(concat("", [`(`, _source, `)\s*\+\s*['"]\(|\$\{\s*(`, _source, `)\s*\}\(`]), line)
	not regex.match(concat("", [`^[^'"\x60]*['"][^'"\x60]*(`, _source, `)`]), line)
	not regex.match(_sanitiser_call, line)
}

# const cb = req.query.cb; ... res.send(`${cb}(...)`) / res.send(cb + '(' ...)
_unvalidated_call(lines, i, line) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	some v in _plain_from_source(prev) | _destructured_from_source(prev)
	_uses_as_callee(line, v)
	not _guarded(lines, j, i, v)
}

_plain_from_source(prev) := {v |
	regex.match(_source, prev)
	not regex.match(_sanitiser_call, prev)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=[^=]`, prev, 1)
	count(m) > 0
	v := m[0][1]
}

# const { callback } = req.query; const { cb: name } = ctx.query
_destructured_from_source(prev) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:req|request|ctx)\.(?:query|params|body|request\.query)\b`, prev, 1)
	count(m) > 0
	some entry in split(m[0][1], ",")
	parts := split(trim_space(entry), ":")
	regex.match(concat("", [`^`, _key, `$`]), trim_space(parts[0]))
	v := trim_space(parts[count(parts) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

_uses_as_callee(line, v) if {
	regex.match(concat("", [`\$\{\s*`, v, `\s*\}\(`]), line)
}

_uses_as_callee(line, v) if {
	code := _strip_strings(line)
	regex.match(concat("", [`(^|[^\w$.])`, v, `\s*\+\s*['"]`]), code)
	regex.match(concat("", [`(^|[^\w$.])`, v, `\s*\+\s*['"]\(`]), line)
}

# A sanitising reassignment, a regular-expression check, an allow-list lookup
# or a comparison with a constant name between the read and the write.
_guarded(lines, j, i, v) if {
	some k in numbers.range(j, i - 1)
	l := lines[k]
	regex.match(concat("", [
		`\b`, v, `\b[^;]*\.replace\s*\(|\.test\s*\(\s*[^)]*\b`, v, `\b|\b`, v, `\b[^;]*\.match\s*\(`,
		`|\.(has|includes|indexOf)\s*\(\s*`, v, `\s*\)`,
		`|\b`, v, `\s*[!=]==?\s*['"]|['"]\s*[!=]==?\s*`, v, `\b`,
	]), l)
}
