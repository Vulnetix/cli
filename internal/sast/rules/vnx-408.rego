# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_408

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-408",
	"name": "Incorrect Behavior Order: Early Amplification",
	"description": "Reports a request-supplied number used, with no upper bound, as an amplification factor: the work an anonymous request triggers grows with a number the client chose rather than with data it sent. Python: `range(n)`, a `while i < n:` bound, `\"x\" * n` / `[0] * n`, `bcrypt.gensalt(n)`, `hashlib.pbkdf2_hmac(..., n)` and `iterations=n`. Node/TypeScript: a `for (...; i < n; ...)` or `while (i < n)` bound, `.repeat(n)`, `new Array(n)`, `Array(n).fill`, `Array.from({ length: n })`, `Buffer.alloc(n)`, `bcrypt.hash(pw, n)`/`genSalt(n)` and `crypto.pbkdf2(..., n, ...)`. n is read from the request (Flask/Django `request.args/form/json/GET/POST/...`, Express/Koa `req.query/body/params/headers`) on the sink line or assigned from it (including destructuring) in the 15 lines above. Not reported: a value clamped with min()/Math.min or compared with a bound on the lines in between, lengths of request data (`len(...)`, `.length`), constants, test files, comments and strings. The CWE's ordering aspect (expensive work before authentication) cannot be seen line by line, so the rule reports the unbounded factor itself.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-408/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [408],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["early-amplification", "cwe-408"],
}

_py_src := `\brequest\.(args|form|values|json|GET|POST|data|query_params|params|headers|cookies|get_json)\b`

_js_src := `\b(req|request|ctx\.request|ctx)\.(query|body|params|headers)\b`

_js_file(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)

_strip(l) := regex.replace(l, concat("", [`"(\\.|[^"\\])*"|'(\\.|[^'\\])*'|`, "`[^`]*`"]), `""`)

# ── Sinks: the expression that sets the amount of work ───────────────────

_py_sinks := [
	`\brange\(\s*(.+)$`,
	`(?:"[^"]*"|'[^']*'|\])\s*\*\s*([A-Za-z_(][^#+\-,]*)`,
	`\bgensalt\(\s*(?:rounds\s*=\s*)?([^,)]+)`,
	`\bpbkdf2_hmac\(\s*[^,]+,[^,]+,[^,]+,\s*([^,)]+)`,
	`[(,]\s*iterations\s*=\s*([^,)=\s][^,)]*)`,
	`\bwhile\s+\(?\s*[\w.]+\s*<=?\s*([^:#]+):`,
]

_js_sinks := [
	`\bfor\s*\([^;]*;\s*[\w.]+\s*<=?\s*([^;]+);`,
	`\bwhile\s*\(\s*[\w.]+\s*<=?\s*([^)]+)\)`,
	`\.repeat\(\s*([^)]+)\)`,
	`\bnew\s+Array\(\s*([^),]+)\)`,
	`\bArray\(\s*([^),]+)\)\s*\.fill`,
	`\bArray\.from\(\s*\{\s*length\s*:\s*([^},]+)`,
	`\bBuffer\.(?:alloc|allocUnsafe|allocUnsafeSlow)\(\s*([^,)]+)`,
	`\bbcrypt\w*\.(?:hash|hashSync)\(\s*[^,]+,\s*([^,)]+)`,
	`\bbcrypt\w*\.genSalt(?:Sync)?\(\s*([^,)]+)`,
	`\bpbkdf2(?:Sync)?\(\s*[^,]+,[^,]+,\s*([^,)]+)`,
]

# A length of data the client already sent is not a chosen factor.
_drop_len(e) := regex.replace(e, `\blen\([^()]*(\([^()]*\)[^()]*)*\)|[\w.\[\]'"]+\.length\b`, "")

_exprs(line, sinks) := {_drop_len(m[1]) |
	some re in sinks
	some m in regex.find_all_string_submatch_n(re, line, -1)
}

_tainted(expr, _, _, src, _) if regex.match(src, expr)

_tainted(expr, lines, i, _, names) if {
	some v in names
	regex.match(concat("", [`\b`, v, `\b`]), expr)
	not _bounded(lines, i, v)
}

# A clamp or a comparison against the value between source and sink.
_bounded(lines, i, v) if {
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	contains(l, v)
	regex.match(concat("", [`\b`, v, `\s*[<>]=?|[<>]=?\s*`, v, `\b|\b(min|clamp|Math\.min)\s*\(|MAX`]), l)
}

# Destructured request fields: const { size, rows: n = 1 } = req.body
_js_destructured(lines, i) := {n |
	some k in numbers.range(max([0, i - 15]), i - 1)
	some m in regex.find_all_string_submatch_n(`(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:req|request|ctx\.request|ctx)\.(?:query|body|params)\b`, lines[k], 1)
	some part in split(m[1], ",")
	p := trim_space(regex.replace(part, `=.*$`, ""))
	p != ""
	n := trim_space(regex.replace(p, `^[^:]*:`, ""))
}

_report(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_msg := "A number taken from the request sets how much work this line does (iterations, repetitions, array size or hash cost) with no upper bound: one request can make the server do unbounded work. Clamp it (min(n, MAX)) or reject values over a limit before using it."

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "request.")
	regex.match(`range\(|\*|gensalt|pbkdf2|iterations|while`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`range\(|\*|gensalt|pbkdf2|iterations|while`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some expr in _exprs(code, _py_sinks)
	not regex.match(`\b(min|clamp)\s*\(`, expr)
	_tainted(expr, lines, i, _py_src, helpers.tainted_names(lines, i, 15, _py_src))
	finding := _report(path, i, line, _msg)
}

findings contains finding if {
	some path, content in input.file_contents
	_js_file(path)
	not helpers.is_test_path(path)
	regex.match(`\b(req|request|ctx)\.`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`for\s*\(|while\s*\(|repeat\(|Array|Buffer\.|bcrypt|pbkdf2`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some expr in _exprs(code, _js_sinks)
	not regex.match(`\b(Math\.min|min|clamp)\s*\(`, expr)
	names := helpers.tainted_names(lines, i, 15, _js_src) | _js_destructured(lines, i)
	_tainted(expr, lines, i, _js_src, names)
	finding := _report(path, i, line, _msg)
}
