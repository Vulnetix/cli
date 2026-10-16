# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_349

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-349",
	"name": "Acceptance of Extraneous Untrusted Data With Trusted Data",
	"description": "A trusted object (verified JWT claims, the server-side session, the authenticated principal) is merged wholesale with the request body or query, so every extra field the client sends (role, sub, isAdmin, tenant) is accepted alongside the data the server vouched for. Reported: in JavaScript/TypeScript, Object.assign(), lodash _.merge/extend/assign/assignIn/defaults/defaultsDeep (and merge/mergeWith/extend/assignIn/defaultsDeep imported by name from lodash) and an object spread {...a, ...b} combining such an object with req.body/query/params/cookies (or ctx.request.body); in Python, .update(), {**a, **b} and dict(a, **b) combining such an object with request.json/get_json()/form/args/values/data/POST/GET/query_params; in Java, putAll(request.getParameterMap()) and Jackson readerForUpdating(...).readValue(request.getInputStream()/getReader()) into such an object. The untrusted side may be inline or a variable assigned from the request in the 15 lines above, and a call may continue over the next two lines. The trusted side is recognised by name (session, claims/*Claims/*_claims, decoded* other than decoded copies of input such as decodedQuery, verified*, jwt payload, principal, current user, auth user/context, req.user/request.user, Koa ctx.state.user, res.locals.user) or as a variable assigned from jwt.verify()/jwt.decode()/jose.jwtVerify()/verifyIdToken() in the 15 lines above. Also reported: ...req.body/query/params spread into the options object of an Express res.render() call, which lets the client set the engine's own options (layout, settings) beside the view data. Not reported: merging individually picked fields ({theme: req.body.theme}), merging into a fresh object ({}, a new map) or into an object not named as trusted (mass assignment onto a model is VNX-915's), merging server-side data, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-349/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [349],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["extraneous-data", "cwe-349"],
}

_trusted_re := `(?i)^(?:(?:req|request|ctx\.state|res\.locals|g|self|this)\.)?(?:session|claims|\w+_claims|\w+claims|jwt_?payload|decoded\w*|verified\w*|principal|current_?user|auth_?(?:user|context|info|claims))$`

_trusted(t, _, _) if {
	regex.match(_trusted_re, t)
	not _decoded_input(t)
}

_trusted(t, _, _) if regex.match(`^(?:req|request|ctx\.state|res\.locals)\.user$`, t)

# A name assigned from a token verification in the 15 lines above
# (const payload = jwt.verify(...), data = jwt.decode(token, key, ...)).
_trusted(t, lines, i) if {
	regex.match(`^[A-Za-z_$][\w$]*$`, t)
	t in helpers.tainted_names(lines, i, 15, `\b(?:jwt|jws|jose|jwtDecode)\.(?:verify|decode|jwtVerify)\(|\bverifyIdToken\(|\bverify_(?:jwt|token|id_token)\(|\bdecode_token\(`)
}

# decodedQuery, decoded_path, decodedUrl: a percent- or base64-decoded copy of
# the input, not a verified token.
_decoded_input(t) if regex.match(`(?i)^decoded_?(?:url|uri|path|query|param|body|input|str|text|html|form|name|value)`, t)

_langs := {
	"js": {
		"exts": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
		"gate": `Object\.assign\(|\.\.\.|\.(?:merge|extend|assign|assignIn|defaults|defaultsDeep)\(|["']lodash(?:[./][\w.]+)?["']`,
		"heads": `Object\.assign\(|\.(?:merge|extend|assign|assignIn|defaults|defaultsDeep)\(|\.\.\.|\b(?:merge|mergeWith|extend|assignIn|defaultsDeep)\(`,
		"patterns": [
			{"re": `^[^\n]*?\bObject\.assign\(\s*([\w.$]+)\s*,\s*([\w.$]+)\s*[,)]`, "both": false},
			{"re": `^[^\n]*?\b(?:_|lodash)\.(?:merge|extend|assign|assignIn|defaults|defaultsDeep)\(\s*([\w.$]+)\s*,\s*([\w.$]+)\s*[,)]`, "both": false},
			{"re": `^[^\n]*?\{\s*\.\.\.([\w.$]+)\s*,\s*\.\.\.([\w.$]+)\s*[,}]`, "both": true},
			# merge imported by name from lodash (import { merge } from "lodash")
			{"re": `^[^\n]*?(?:^|[^.\w$])(?:merge|mergeWith|extend|assignIn|defaultsDeep)\(\s*([\w.$]+)\s*,\s*([\w.$]+)\s*[,)]`, "both": false, "lodash": true},
		],
		"src": `^(?:req|request|ctx\.request|ctx)\.(?:body|query|params|cookies)\b`,
		"src_line": `\b(?:req|request|ctx\.request|ctx)\.(?:body|query|params|cookies)\b`,
	},
	"py": {
		"exts": {".py"},
		"gate": `request\.`,
		"heads": `\.update\(|\*\*|\bdict\(`,
		"patterns": [
			{"re": `^[^\n]*?\b([\w.]+)\.update\(\s*([\w.]+(?:\(\))?)\s*\)`, "both": false},
			{"re": `^[^\n]*?\{\s*\*\*([\w.]+(?:\(\))?)\s*,\s*\*\*([\w.]+(?:\(\))?)\s*[,}]`, "both": true},
			{"re": `^[^\n]*?\bdict\(\s*([\w.]+)\s*,\s*\*\*([\w.]+(?:\(\))?)\s*[,)]`, "both": false},
		],
		"src": `^request\.(?:json|form|args|values|data|POST|GET|query_params|get_json)\b`,
		"src_line": `\brequest\.(?:json|form|args|values|data|POST|GET|query_params|get_json)\b`,
	},
	"java": {
		"exts": {".java"},
		"gate": `getParameterMap\(|readerForUpdating\(`,
		"heads": `\.putAll\(|readerForUpdating\(`,
		"patterns": [
			{"re": `^[^\n]*?\b([\w.]+)\.putAll\(\s*([\w.]+(?:\(\))?)\s*\)`, "both": false},
			{"re": `^[^\n]*?readerForUpdating\(\s*([\w.]+)\s*\)\s*\.readValue\(\s*([\w.]+(?:\(\))?)\s*[,)]`, "both": false},
		],
		"src": `^\w*[Rr]equest\.(?:getParameterMap|getInputStream|getReader)\(\)$`,
		"src_line": `\b\w*[Rr]equest\.(?:getParameterMap|getInputStream|getReader)\(`,
	},
}

_untrusted(lang, s, lines, i) if regex.match(lang.src, s)

_untrusted(lang, s, lines, i) if {
	regex.match(`^[A-Za-z_]\w*$`, s)
	s in _whole_request_names(lines, i, lang.src_line)
}

# Names assigned from the request in the 15 lines above, except an object or
# dict literal that picks fields ({theme: req.body.theme}), which holds only
# what the handler chose to copy.
_whole_request_names(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(src, prev)
	not regex.match(`[^=!<>]=\s*\{`, prev)
	v := helpers.assigned_first(prev)
}

# A Java declaration whose generic type has a comma (Map<String, String[]> p =
# request.getParameterMap()), which assigned_first does not parse.
_untrusted(lang, s, lines, i) if {
	regex.match(`^[A-Za-z_]\w*$`, s)
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(lang.src_line, lines[j])
	regex.match(concat("", [`>\s+`, s, `\s*=[^=]`]), lines[j])
}

_pattern_applies(p, _) if not object.get(p, "lodash", false)

_pattern_applies(p, true) if object.get(p, "lodash", false)

_lodash_named(content) := false if not _lodash_import(content)

_lodash_named(content) := true if _lodash_import(content)

_lodash_import(content) if {
	regex.match(`(?:\bimport\s*\{[^}]*\b(?:merge|mergeWith|extend|assignIn|defaultsDeep)\b[^}]*\}\s*from|\brequire\(\s*)\s*["']lodash(?:-es)?["']|\bimport\s+\w+\s+from\s+["']lodash[./](?:merge|mergeWith|extend|assignIn|defaultsDeep)["']|=\s*require\(\s*["']lodash[./](?:merge|mergeWith|extend|assignIn|defaultsDeep)["']`, content)
}

_pairs(p, m) := {[m[1], m[2]], [m[2], m[1]]} if p.both

_pairs(p, m) := {[m[1], m[2]]} if not p.both

# The call sits inside a string literal on this line.
_quoted_head(line, heads) if regex.match(sprintf(`^[^"'\x60]*["'\x60][^"'\x60]*(?:%s)`, [heads]), line)

findings contains finding if {
	some path, content in input.file_contents
	some lang in _langs
	some e in lang.exts
	endswith(path, e)
	regex.match(lang.gate, content)
	ln := _lodash_named(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(lang.heads, line)
	not helpers.is_comment_line(line)
	not _quoted_head(line, lang.heads)
	not regex.match(`^\s*[rbuf]*["'\x60]`, line)
	text := concat("\n", array.slice(lines, i, min([count(lines), i + 3])))
	some p in lang.patterns
	_pattern_applies(p, ln)
	some m in regex.find_all_string_submatch_n(p.re, text, 1)
	some pr in _pairs(p, m)
	_trusted(pr[0], lines, i)
	_untrusted(lang, pr[1], lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is merged wholesale with request data (%s), so any extra field the client sends is accepted as trusted. Copy only the fields you expect, after validating them", [pr[0], pr[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Express/hbs/pug: spreading the request into the render options lets the
# client set the engine's own options (layout, settings, cache), beside the
# view data the handler supplies.
_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

findings contains finding if {
	some path, content in input.file_contents
	some e in _js_exts
	endswith(path, e)
	contains(content, ".render(")
	regex.match(`\.\.\.\s*(?:req|request)\.(?:body|query|params)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.\.\.\s*(?:req|request)\.(?:body|query|params)\b`, line)
	prefix := substring(line, 0, indexof(line, "..."))
	strings.count(prefix, "\"") % 2 == 0
	strings.count(prefix, "'") % 2 == 0
	strings.count(prefix, "`") % 2 == 0
	not helpers.is_comment_line(line)
	regex.match(`\bres\.render\(\s*[^,]+,\s*\{`, concat("\n", array.slice(lines, max([0, i - 2]), i + 1)))
	finding := {
		"rule_id": metadata.id,
		"message": "The request is spread into the template render options, so the client can set the engine's own options (layout, settings) beside the view data. Pass only the fields the view needs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
