# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1288

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1288",
	"name": "Improper Validation of Consistency within Input",
	"description": "A server-side handler reads a password-confirmation field from the request (passwordRepeat, repeatPassword, confirmPassword, password_confirm(ation), confirm_password, password2, retypePassword, passwordAgain and their spellings) but nothing in the same file compares it with the password, so the two fields of one request are never checked for consistency and a typo or a forged request sets a password the user did not confirm (the OWASP Juice Shop 'Repetitive Registration' flaw). Reported in JavaScript/TypeScript (req/request.body, req.query, ctx.request.body: property, bracket and destructuring reads) and Python (Flask/Django/DRF request.form/POST/values/args/json/get_json()/data: subscript and .get() reads). The field counts as checked when the file compares it, or the variable assigned from it, with == / != / === / !== against something other than undefined, null, None, a number, a boolean or an empty string, or passes it to compare_digest/constant_time_compare/timingSafeEqual, or names it in a schema reference (Joi.ref, sameAs, equalTo). Not reported: client-side code that only sends the field, comments, and string literals. Other consistency rules (start before end, totals that match their items) are not detected.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1288/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1288],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["input-validation-data", "cwe-1288"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_lang(path) := "js" if {
	some e in _js_exts
	endswith(path, e)
	not endswith(path, ".min.js")
	not contains(path, "node_modules/")
}

_lang(path) := "py" if endswith(path, ".py")

_name_re := `(?i:(?:new_?)?pass(?:word|wd)?_?(?:repeat|confirm(?:ation)?|again|verify|check|2)|(?:repeat|confirm|retype|re_?enter|verify)_?(?:new_?)?pass(?:word|wd))`

_gate := `(?i)pass(?:word|wd)?_?(?:repeat|confirm|again|verify|check|2)|(?:repeat|confirm|retype|re_?enter|verify)_?(?:new_?)?pass`

_src := {
	"js": `(?:\b(?:req|request)\.(?:body|query)|\bctx\.request\.body)`,
	"py": `\brequest\.(?:form|POST|values|args|json|get_json\([^)]*\)|data|GET)`,
}

# The confirmation field a line reads from the request: [field, assigned var].
_reads("js", line) := {[f, v] |
	m := regex.find_all_string_submatch_n(concat("", [_src.js, `(?:\.(`, _name_re, `)\b|\[\s*['"](`, _name_re, `)['"]\s*\])`]), line, -1)
	some x in m
	f := concat("", [x[1], x[2]])
	v := _lhs(line)
} | _destructured(line)

_destructured(line) := {[f, f] |
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*`, _src.js, `\s*;?\s*$`]), line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	segs := split(split(part, "=")[0], ":")
	f := trim_space(segs[0])
	regex.match(concat("", [`^`, _name_re, `$`]), f)
}

_reads("py", line) := {[f, v] |
	m := regex.find_all_string_submatch_n(concat("", [_src.py, `(?:\[\s*['"](`, _name_re, `)['"]\s*\]|\.get\(\s*['"](`, _name_re, `)['"])`]), line, -1)
	some x in m
	f := concat("", [x[1], x[2]])
	v := _lhs(line)
}

_lhs(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_lhs(line) := "" if {
	not regex.match(`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*[^=]`, line)
}

_literal(x) if regex.match(`^(?:undefined|null|None|true|false|True|False|\d+|''|""|\[\]|\{\})$`, trim_space(x))

_has_token(s, tokens) if {
	some t in tokens
	t != ""
	regex.match(concat("", [`(?:^|[^\w$])`, t, `(?:$|[^\w$])`]), s)
}

_compares(lines, tokens) if {
	some l in lines
	regex.match(`[=!]=`, l)
	not helpers.is_comment_line(l)
	pairs := regex.find_all_string_submatch_n(`([\w$.\[\]'"]+)\s*(?:===?|!==?)\s*([\w$.\[\]'"]+)`, l, -1)
	some p in pairs
	_side_pair(p[1], p[2], tokens)
}

_compares(lines, tokens) if {
	some l in lines
	regex.match(`compare_digest\(|constant_time_compare\(|timingSafeEqual\(|\bref\(|sameAs|equalTo|\.equals\(|(?:^|[^.\w$])\w*(?i:match|same|equal|compare)\w*\(`, l)
	not helpers.is_comment_line(l)
	_has_token(l, tokens)
}

_side_pair(a, b, tokens) if {
	_has_token(a, tokens)
	not _literal(b)
}

_side_pair(a, b, tokens) if {
	_has_token(b, tokens)
	not _literal(a)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate, content)
	regex.match(_src[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	some r in _reads(lang, line)
	[f, v] := r
	not _compares(lines, {f, v})
	not _read_earlier(lines, i, lang, f)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Request field '%s' (the password confirmation) is read but never compared with the password; check that the two fields agree before saving", [f]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# One finding per field per file: the first line that reads it.
_read_earlier(lines, i, lang, f) if {
	i > 0
	some j in numbers.range(0, i - 1)
	contains(lines[j], f)
	not helpers.is_comment_line(lines[j])
	some r in _reads(lang, lines[j])
	r[0] == f
}
