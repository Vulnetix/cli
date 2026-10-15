# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_472

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-472",
	"name": "External Control of Assumed-Immutable Web Parameter",
	"description": "A value the server should own is taken from the client. Reported in JavaScript/TypeScript server code: a price-like field (price, unitPrice, total, totalPrice, subtotal, cost, discount, fee, tax, shipping, shippingCost) or a privilege field (role, roles, isAdmin, admin, isStaff, isSuperuser, permissions, accessLevel, userType) read from req/request/ctx.request body, query, params or cookies (`req.body.price`, `req.query['discount']`, `const { unitPrice } = ctx.request.body`, `req.cookies.isAdmin === 'true'`), including a destructuring written over several lines (`const {` / `totalPrice,` / `} = req.body;`). In HTML and template files (html, ejs, hbs, handlebars, mustache, njk, pug, vue, jsx, tsx): a hidden form input whose name is one of those fields or userId/user_id/accountId/ownerId, the field the form assumes the user will not edit. Not reported: admin back-office handlers (a file under an admin/ directory, or a route whose path or middleware names admin, such as requireAdmin), where setting prices and roles is the job; a price-like field that is only compared (`req.body.price !== product.price` is validation), fields the user legitimately chooses (amount, quantity, productId), values read from a server-side lookup or a fetch response, hidden inputs carrying CSRF tokens, ids of the item being acted on or redirects, test sources, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-472/",
	"languages": ["node", "html"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [472],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["externally-controllable-web-param", "cwe-472"],
}

_js_exts := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}

_tpl_exts := {".html", ".htm", ".ejs", ".hbs", ".handlebars", ".mustache", ".njk", ".pug", ".vue", ".jsx", ".tsx"}

_price := `(?i)^(?:unit_?price|price|total|total_?price|total_?cost|sub_?total|cost|discount|discount_?(?:rate|percent)|fee|tax|shipping|shipping_?(?:cost|fee))$`

_priv := `(?i)^(?:role|roles|is_?admin|admin|is_?staff|is_?superuser|permissions?|access_?level|user_?type)$`

_owner := `(?i)^(?:user_?id|account_?id|owner_?id)$`

_req := `\b(?:req|request|ctx\.request|ctx)\s*(?:\?\.|\.)\s*(?:body|query|params|cookies|signedCookies)`

_field_read := concat("", [_req, `\s*(?:\?\.|\.)\s*([A-Za-z_]\w*)|`, _req, `\s*\[\s*['"]([A-Za-z_]\w*)['"]\s*\]`])

_destructure := concat("", [`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*`, _req, `\b`])

_code(line) := regex.replace(
	regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``"),
	`//.*$`, "",
)

_name(m) := m[1] if m[1] != ""

_name(m) := m[2] if m[1] == ""

_compared(code, f) if regex.match(concat("", [f, `['"\]]*\s*\]?\s*(?:===?|!==?|<=?|>=?)`]), code)

_compared(code, f) if regex.match(concat("", [`(?:===?|!==?|<=?|>=?)\s*`, _req, `\s*(?:\?\.|\.|\[\s*['"])\s*`, f, `\b`]), code)

# Reads of a field through the request object; the raw line keeps the key of
# req.body['role'], the stripped code rules out strings and comments.
_js_bad(code, raw) if {
	some m in regex.find_all_string_submatch_n(_field_read, raw, -1)
	f := _name(m)
	regex.match(_priv, f)
	regex.match(concat("", [_req, `\s*(?:\?\.|\.)\s*`, f, `\b|`, _req, `\s*\[\s*''`]), code)
}

_js_bad(code, raw) if {
	some m in regex.find_all_string_submatch_n(_field_read, raw, -1)
	f := _name(m)
	regex.match(_price, f)
	regex.match(concat("", [_req, `\s*(?:\?\.|\.)\s*`, f, `\b|`, _req, `\s*\[\s*''`]), code)
	not _compared(raw, f)
}

_js_bad(code, _) if {
	some m in regex.find_all_string_submatch_n(_destructure, code, -1)
	some part in split(m[1], ",")
	key := trim_space(split(trim_space(part), ":")[0])
	_price_or_priv(key)
}

_price_or_priv(k) if regex.match(_price, k)

_price_or_priv(k) if regex.match(_priv, k)

findings contains finding if {
	some path, content in input.file_contents
	some ext in _js_exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(_req, content)
	lines := split(content, "\n")
	some i, line in lines
	_req_word(line)
	regex.match(_req, line)
	not helpers.is_comment_line(line)
	_js_bad(_code(line), line)
	not _admin_scope(path, lines, i)
	finding := _finding(path, i, line, _js_msg)
}

_js_msg := "A price or privilege value is read from the request: the client can set it to anything. Look the price up on the server and take the role from the authenticated session"

# A destructuring broken over lines: `const {` / `  totalPrice,` / `} = req.body;`.
findings contains finding if {
	some path, content in input.file_contents
	some ext in _js_exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*\}\s*=\s*(?:req|request|ctx\.request|ctx)\s*\.`, content)
	lines := split(content, "\n")
	some c, cl in lines
	regex.match(concat("", [`^\s*\}\s*=\s*`, _req, `\b`]), cl)
	some o in numbers.range(max([0, c - 20]), c - 1)
	regex.match(`\b(?:const|let|var)\s*\{\s*$`, _code(lines[o]))
	not _brace_between(lines, o + 1, c - 1)
	some i in numbers.range(o + 1, c - 1)
	km := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$]*)\s*(?::\s*[A-Za-z_$][\w$]*)?\s*(?:=[^,]*)?,?\s*$`, _code(lines[i]), 1)
	count(km) > 0
	_price_or_priv(km[0][1])
	not _admin_scope(path, lines, i)
	finding := _finding(path, i, lines[i], _js_msg)
}

_brace_between(lines, a, b) if {
	some k in numbers.range(a, b)
	regex.match(`[{}]`, _code(lines[k]))
}

# Admin back-office code sets prices and roles by design: a file under an
# admin directory, or a handler whose route or middleware names admin.
_admin_scope(path, _, _) if regex.match(`(?i)(?:^|/)admin/`, path)

_admin_route := "(?i)['\"`]/(?:[^'\"`]*/)?admin\\b|\\b(?:require|ensure|is|check|must_?be|only)_?admin\\w*\\b|\\badmin_?(?:only|required|auth\\w*|guard|middleware)\\b"

_admin_scope(_, lines, i) if {
	routes := [j |
		some j in numbers.range(max([0, i - 30]), i)
		regex.match(`\.(?:get|post|put|patch|delete|all)\s*\(`, lines[j])
	]
	count(routes) > 0
	regex.match(_admin_route, lines[max(routes)])
}

_req_word(l) if contains(l, "body")

_req_word(l) if contains(l, "query")

_req_word(l) if contains(l, "params")

_req_word(l) if contains(l, "ookies")

_hidden_word(s) if contains(s, "hidden")

_hidden_word(s) if contains(s, "HIDDEN")

_hidden_word(s) if contains(s, "Hidden")

_input_tag :=`(?i)<input\b[^>]*>|\binput\s*\([^)]*\)`

_hidden_field(tag) := f if {
	regex.match(`(?i)\btype\s*=\s*["']?hidden\b`, tag)
	m := regex.find_all_string_submatch_n(`(?i)\bname\s*=\s*["']([A-Za-z_][\w-]*)["']`, tag, 1)
	count(m) > 0
	f := m[0][1]
}

_tpl_field(f) if _price_or_priv(f)

_tpl_field(f) if regex.match(_owner, f)

findings contains finding if {
	some path, content in input.file_contents
	some ext in _tpl_exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	_hidden_word(content)
	lines := split(content, "\n")
	some i, line in lines
	_hidden_word(line)
	not regex.match(`^\s*(?://|<!--|\{\{!|<%#)`, line)
	some tag in regex.find_n(_input_tag, line, -1)
	f := _hidden_field(tag)
	_tpl_field(f)
	finding := _finding(path, i, line, sprintf("Hidden form field %q carries a value the server should own: a hidden input is not read-only, the client can submit any value. Derive it on the server from the session or the item id", [f]))
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
