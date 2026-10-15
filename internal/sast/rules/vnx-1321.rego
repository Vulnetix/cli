# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1321

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1321",
	"name": "Prototype pollution through unguarded computed-key assignment",
	"description": "JavaScript/TypeScript code that writes through a computed key an attacker can set to __proto__ or constructor, so the write lands on Object.prototype and every object in the process inherits it. Reported: (1) a hand-written recursive merge/extend: inside a for...in, for...of Object.keys/getOwnPropertyNames/entries/Reflect.ownKeys or Object.keys(...).forEach loop over a source object, a call that passes target[key] together with source[key] (deepMerge(target[key], source[key]), extend(dst[k] || {}, src[k]), Object.assign(t[k], s[k])); (2) a hand-written set-by-path: a loop that walks cur = cur[part] followed within a few lines by cur[...] = value; (3) a nested assignment obj[A][B] = v or obj[A].x = v whose first key A is request data (req.body/query/params/cookies/headers, ctx.query, ctx.request.body), directly or through a variable assigned from it in the 10 lines above. Not reported: code whose function window (15 lines above to the line) names __proto__, constructor or prototype, or uses Object.create(null), a Map, or a safe-key/forbidden-key check; a shallow one-level copy (dst[k] = src[k] only sets dst's own prototype); nested assignments whose keys are constants or loop indices; comments and string literals. Library merges called with request data (lodash merge/set, $.extend(true, ...)) are VNX-NODE-006.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1321/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1321],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["prototype-pollution", "cwe-1321"],
}

_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_js(path) if {
	some e in _exts
	endswith(path, e)
}

_skip(path) if endswith(path, ".min.js")

_skip(path) if contains(path, "node_modules/")

_skip(path) if endswith(path, ".d.ts")

# String literals blanked so a key named in a message is not code.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``")

_guard_re := `__proto__|['"\x60](?:constructor|prototype)['"\x60]|\.constructor\s*[!=]==?|\bisPrototypeOf\b|Object\.create\(\s*null\s*\)|new Map\(|(?i:unsafe_?keys?|forbidden|blocked_?keys|deny_?list|block_?list|safe_?key|is_?safe|valid_?key|dangerous_?keys?|polluti)`

_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 15, 0)
	regex.match(_guard_re, w)
}

# A collection naming __proto__ declared anywhere in the file (a module-level
# RESERVED = new Set([...])), consulted with .has/.includes/.indexOf nearby.
_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 15, 0)
	regex.match(`\.(?:has|includes|indexOf)\(`, w)
	some l in lines
	contains(l, "__proto__")
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=`, l, 1)
	count(m) > 0
	regex.match(concat("", [`\b`, m[0][1], `\s*\.(?:has|includes|indexOf)\(`]), w)
}

# ── (1) recursive merge ──────────────────────────────────────────────────

_loop_heads(line) := {[k, s, v] |
	m := regex.find_all_string_submatch_n(`\bfor\s*\(\s*(?:const|let|var)?\s*(\w+)\s+(?:in|of)\s+(?:(?:Object\.(?:keys|getOwnPropertyNames)|Reflect\.ownKeys)\(\s*)?([\w.]+)`, line, -1)
	some x in m
	k := x[1]
	s := x[2]
	v := ""
} | {[k, s, v] |
	m := regex.find_all_string_submatch_n(`\bfor\s*\(\s*(?:const|let|var)\s*\[\s*(\w+)\s*,\s*(\w+)\s*\]\s+of\s+Object\.entries\(\s*([\w.]+)`, line, -1)
	some x in m
	k := x[1]
	v := x[2]
	s := x[3]
} | {[k, s, v] |
	m := regex.find_all_string_submatch_n(`\bObject\.entries\(\s*([\w.]+)\s*\)\s*\.forEach\(\s*(?:function\s*)?\(\s*\[\s*(\w+)\s*,\s*(\w+)\s*\]`, line, -1)
	some x in m
	s := x[1]
	k := x[2]
	v := x[3]
} | {[k, s, v] |
	m := regex.find_all_string_submatch_n(`\bObject\.keys\(\s*([\w.]+)\s*\)\s*\.forEach\(\s*(?:function\s*)?\(?\s*(\w+)`, line, -1)
	some x in m
	s := x[1]
	k := x[2]
	v := ""
}

_q(s) := regex.replace(s, `\.`, `\.`)

_src_arg(s, k, "") := concat("", [_q(s), `\[`, k, `\]`])

_src_arg(s, k, v) := concat("", [`(?:`, _q(s), `\[`, k, `\]|\b`, v, `\b)`]) if v != ""

_merge_call(c, k, s, v) if {
	not regex.match(`\.(?:apply|call|bind|push|unshift|concat|splice|set|add)\(\s*[\w.$]+\[`, c)
	re := concat("", [`\b[\w.$]+\(\s*[\w.$]+\[`, k, `\]\s*(?:(?:\|\||\?\?)\s*\{\s*\}\s*)?,\s*`, _src_arg(s, k, v), `\s*[,)]`])
	regex.match(re, c)
}

findings contains finding if {
	some path, content in input.file_contents
	_js(path)
	not _skip(path)
	regex.match(`\bfor\s*\(|\.forEach\(`, content)
	contains(content, "[")
	lines := split(content, "\n")
	some h, head in lines
	contains(head, "for")
	count(head) < 400
	not helpers.is_comment_line(head)
	some lh in _loop_heads(_code(head))
	[k, s, v] := lh
	some i in numbers.range(h, min([h + 8, count(lines) - 1]))
	line := lines[i]
	contains(line, "(")
	not helpers.is_comment_line(line)
	_merge_call(_code(line), k, s, v)
	not _guarded(lines, i)
	finding := _finding(path, i, line, "Recursive merge passes target[key] for a key read from the source object; a source key of __proto__ or constructor writes onto Object.prototype. Skip those keys (or merge into Object.create(null))")
}

# ── (2) set-by-path walk ─────────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	_js(path)
	not _skip(path)
	regex.match(`(?m)^\s*(\w+)\s*=\s*\w+\[\w+\]\s*;?\s*$`, content)
	lines := split(content, "\n")
	some k, walk in lines
	contains(walk, "[")
	contains(walk, "=")
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*=\s*(\w+)\[\w+\]\s*;?\s*$`, walk, 1)
	count(m) > 0
	m[0][1] == m[0][2]
	cur := m[0][1]
	_in_loop(lines, k)
	some i in numbers.range(k + 1, min([k + 8, count(lines) - 1]))
	line := lines[i]
	not helpers.is_comment_line(line)
	regex.match(concat("", [`^\s*`, cur, `\[[^\]]+(?:\[[^\]]*\][^\]]*)*\]\s*=[^=]`]), _code(line))
	not _guarded(lines, i)
	finding := _finding(path, i, line, "Set-by-path walks cur = cur[part] and then assigns through it; a path segment of __proto__ or constructor reaches Object.prototype. Reject those segments before walking")
}

_in_loop(lines, k) if {
	some j in numbers.range(max([0, k - 4]), k - 1)
	regex.match(`\b(for|while)\s*\(|\.forEach\(|\.reduce\(`, lines[j])
}

# ── (3) nested assignment keyed by request data ──────────────────────────

_req_re := `\b(?:req|request)\.(?:body|query|params|cookies|headers)\b|\bctx\.(?:query|params|request\.body)\b`

_tainted(lines, i) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	regex.match(_req_re, prev)
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)?\s*(\w+)\s*(?::\s*[\w<>\[\]| ]+)?=\s*[^=]`, prev, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"const", "let", "var"}
} | {v |
	# const { section, key: k, value } = req.body
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	regex.match(_req_re, prev)
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, prev, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	names := regex.find_all_string_submatch_n(`^\s*(?:[A-Za-z_$][\w$]*\s*:\s*)?([A-Za-z_$][\w$]*)`, part, 1)
	count(names) > 0
	v := names[0][1]
}

_key_tainted(key, _) if regex.match(_req_re, key)

_key_tainted(key, names) if {
	some v in names
	regex.match(concat("", [`^\s*`, v, `\s*$`]), key)
}

# The key was checked against an allowlist in the lines above:
# ALLOWED.includes(key), allowed.has(key), list.indexOf(key) or key in table.
_key_allowlisted(lines, i, key) if {
	k := trim_space(key)
	regex.match(`^[A-Za-z_$][\w$]*$`, k)
	w := helpers.code_window(lines, i, 15, 0)
	regex.match(concat("", [`\.(?:includes|has|indexOf)\(\s*`, k, `\s*\)|\b`, k, `\s+in\s+[A-Za-z_$]`]), w)
}

findings contains finding if {
	some path, content in input.file_contents
	_js(path)
	not _skip(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	regex.match(`\]\s*(?:\[[^\]]+\]|\.\w+)\s*=[^=>]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "]")
	contains(line, "=")
	count(line) < 400
	not helpers.is_comment_line(line)
	c := _code(line)
	m := regex.find_all_string_submatch_n(`[\w$\]\)]\[([^\[\]]+)\]\s*(?:\[[^\]]+\]|\.\w+)\s*=[^=>]`, c, -1)
	some x in m
	_key_tainted(x[1], _tainted(lines, i))
	not _guarded(lines, i)
	not _key_allowlisted(lines, i, x[1])
	finding := _finding(path, i, line, "Nested assignment uses a request-controlled key; obj[\"__proto__\"][k] = v writes onto Object.prototype. Validate the key against an allowlist or use a Map")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
