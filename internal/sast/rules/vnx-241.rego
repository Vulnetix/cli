# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_241

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-241",
	"name": "Improper Handling of Unexpected Data Type",
	"description": "A request value whose type the client chooses is used as if it were a string, with no type check. Node.js/TypeScript: a string method or .length (toLowerCase, toUpperCase, trim, split, replace, indexOf, includes, startsWith, endsWith, match, search, substring, substr, slice, charAt, padStart, normalize, localeCompare, concat, repeat) on a value of req.query or req.body, which the default extended parser turns into an array or object for ?a[]=x or a JSON body, inline or through a variable assigned (a TypeScript `as string` cast included, since it checks nothing at run time) or destructured from req.query/req.body in the eight lines above. An array makes indexOf('..') or includes() checks pass, an object makes trim() throw. Python (Flask): a str method (lower, upper, strip, split, replace, startswith, endswith, encode, casefold) on a value of request.json or request.get_json(), which may be a number, list, dict or null, inline or through one assignment. Not reported: a value checked with typeof / isinstance(..., str) in the ten lines above, a value coerced with String() or str(), files that validate requests with express-validator, celebrate, joi, zod, yup or ajv, req.params and Flask request.args/form (always strings), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-241/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [241],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unexpected-data-type", "cwe-241", "type-confusion", "input-validation"],
}

# Bracket access with a literal key becomes dotted access; every other string
# literal is blanked, so text that quotes the pattern is not code.
_norm(line) := c if {
	a := regex.replace(line, `\[\s*["']([A-Za-z_]\w*)["']\s*\]`, ".$1")
	b := regex.replace(a, `(^|[^fFrRbB\w"'])"(?:[^"\\]|\\.)*"`, `$1""`)
	c := regex.replace(b, `(^|[^fFrRbB\w"'])'(?:[^'\\]|\\.)*'`, `$1''`)
}

_esc(s) := regex.replace(s, `([.\[\]()?*+])`, `\$1`)

# ── Node.js ──────────────────────────────────────────────────────────────

_js_ext(path) if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx)$`, path)

_js_methods := `(?:toLowerCase|toUpperCase|toLocaleLowerCase|toLocaleUpperCase|trim|trimStart|trimEnd|split|replace|replaceAll|indexOf|lastIndexOf|includes|startsWith|endsWith|match|matchAll|search|substring|substr|slice|charAt|charCodeAt|padStart|padEnd|normalize|localeCompare|concat|repeat|length)\b`

_js_inline_re := concat("", [`(\breq\.(?:query|body)(?:\.\w+)+?)\??\.`, _js_methods])

_js_validated(content) if regex.match(`express-validator|\bcelebrate\b|\bjoi\b|["']zod["']|\byup\b|\bajv\b|\bJoi\.`, content)

_js_assigned(lines, i) := {v |
	some j in numbers.range(max([0, i - 8]), i - 1)
	j < i
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*(?:<\w+>\s*)?req\.(?:query|body)(?:\.\w+)*(?:\s+as\s+[\w<>\[\]| ]+?)*\s*;?\s*$`, _norm(lines[j]), 1)
	count(m) == 1
	v := m[0][1]
}

_js_destructured(lines, i) := {n |
	some j in numbers.range(max([0, i - 8]), i - 1)
	j < i
	m := regex.find_all_string_submatch_n(`\{([^{}]*)\}\s*(?::\s*[^=]+)?=\s*req\.(?:query|body)\s*;?\s*$`, lines[j], 1)
	count(m) == 1
	some part in split(m[0][1], ",")
	n := trim_space(regex.replace(part, `^[^:]*:|=.*$`, ""))
	regex.match(`^[A-Za-z_$][\w$]*$`, n)
}

_js_guarded(lines, i, expr) if {
	w := helpers.code_window(lines, i, 10, 0)
	regex.match(concat("", [`\btypeof\s*\(?\s*`, _esc(expr), `\b|\bisString\(\s*`, _esc(expr), `\b|\bArray\.isArray\(\s*`, _esc(expr), `\b`]), _norm(w))
}

_js_inline_exprs(code) := {m[1] | some m in regex.find_all_string_submatch_n(_js_inline_re, code, -1)}

_js_hop_exprs(lines, i, code) := {v |
	some v in _js_assigned(lines, i) | _js_destructured(lines, i)
	regex.match(concat("", [`(?:^|[^\w$.])`, _esc(v), `(?:\.\w+)*?\??\.`, _js_methods]), code)
}

findings contains finding if {
	some path, content in input.file_contents
	_js_ext(path)
	regex.match(`\breq\.(?:query|body)\b`, content)
	not _js_validated(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _norm(line)
	regex.match(concat("", [`\.`, _js_methods]), code)
	exprs := {e |
		some e in _js_inline_exprs(code) | _js_hop_exprs(lines, i, code)
		not _js_guarded(lines, i, e)
	}
	count(exprs) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s comes from req.query/req.body and is used as a string with no type check: a client can send an array or object instead (?x[]=a, a JSON body), which bypasses indexOf/includes checks or throws. Check typeof === 'string' first", [concat(", ", sort(exprs))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Python (Flask JSON) ──────────────────────────────────────────────────

_py_methods := `\.(?:lower|upper|strip|lstrip|rstrip|split|rsplit|replace|startswith|endswith|encode|casefold|title|capitalize)\(`

_py_access := `(?:\.\w+|\.get\([^()]*\))`

_py_inline_re := concat("", [`\brequest\.(?:json|get_json\([^()]*\))`, `(?:\.\w+|\.get\([^()]*\))+?`, _py_methods])

_py_source := `\brequest\.(?:json|get_json)\b`

_py_names(lines, i) := {v |
	some j in numbers.range(max([0, i - 8]), i - 1)
	j < i
	prev := _norm(lines[j])
	regex.match(_py_source, prev)
	regex.match(`=\s*request\.(?:json|get_json\([^()]*\))(?:\.\w+|\.get\([^()]*\))?\s*(?:#.*)?$`, prev)
	not startswith(trim_space(prev), "#")
	v := helpers.assigned_first(prev)
}

_py_guarded(lines, i, v) if {
	w := helpers.code_window(lines, i, 10, 0)
	regex.match(concat("", [`\bisinstance\(\s*`, _esc(v), `\b`]), w)
}

_py_hit(_, _, code) if regex.match(_py_inline_re, code)

_py_hit(lines, i, code) if {
	some v in _py_names(lines, i)
	regex.match(concat("", [`(?:^|[^\w.])`, v, _py_access, `*?`, _py_methods]), code)
	not _py_guarded(lines, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\brequest\.(?:json|get_json)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	not startswith(trim_space(line), "#")
	code := _norm(line)
	regex.match(_py_methods, code)
	_py_hit(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "A request.json value is used as a str with no type check: JSON lets the client send a number, list, object or null instead, which raises AttributeError. Check isinstance(value, str) or validate the body with a schema",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
