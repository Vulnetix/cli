# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_840

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-840",
	"name": "Business Logic Error: Client-Controlled Monetary Value",
	"description": "A monetary value read from the HTTP request (a request field named amount, price, total, subtotal, discount, cost, fee or balance, e.g. req.body.amount, const { amount } = req.body, const price: number = req.body.price, request.form[\"total\"], request.json.get(\"discount_percent\")) used directly, or through one assignment, as what the server charges or books: an amount/unit_amount/total/subtotal/discount/balance key, shorthand property or keyword argument (payment-provider calls such as stripe.paymentIntents.create({ amount }) or stripe.Charge.create(amount=...)), an assignment to an order's .total/.amount/.subtotal/.discount or an account's .balance (including += and -=), or a total computed by arithmetic on the client value. The client decides what it pays, or moves a negative amount. JavaScript/TypeScript and Python. Not reported: a price looked up server-side (product.price * qty), request fields that are identifiers or codes (productId, coupon_code, quantity), a client value compared with a server value or range-checked in an if before use, catalogue edits that set a product's .price, query filters (a nested { $gte: ... } operator object), and the pattern in comments or strings. Flows through helper functions or across files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-840/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [840],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["business-logic", "price-tampering", "payments", "cwe-840"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_money := `(?i)^\w*(?:price|amount|total|discount|cost|fee|balance)(?:_?(?:percent|pct|cents|value|amount))?$`

# A request access and the field name it reads.
_access_re := {
	"js": `\breq(?:uest)?\.(?:body|query|params)(?:\.|\[\s*['"])(\w+)`,
	"py": `\brequest\.(?:json|form|args|values|data|GET|POST|get_json\(\s*\))\s*(?:\.get\s*\(\s*|\[\s*)['"](\w+)['"]`,
}

_gate := {
	"js": `req(?:uest)?\.(?:body|query|params)`,
	"py": `request\.(?:json|form|args|values|data|GET|POST|get_json)`,
}

# The line reads a money-named request field.
_money_source(lang, line) if {
	some m in regex.find_all_string_submatch_n(_access_re[lang], line, -1)
	regex.match(_money, m[1])
}

# Destructuring: const { amount, currency } = req.body
_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?req(?:uest)?\.(?:body|query|params)\b`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	n := trim_space(split(trim_space(part), ":")[count(split(trim_space(part), ":")) - 1])
	regex.match(_money, n)
}

# Names that hold a client-supplied money value in the 15 lines above i.
_tainted(lang, lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	_money_source(lang, prev)
	v := helpers.assigned_first(prev)
} | {v |
	lang == "js"
	some j in numbers.range(max([0, i - 15]), i - 1)
	some v in _destructured(lines[j])
} | {v |
	lang == "js"
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	contains(prev, ":")
	_money_source(lang, prev)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[\w<>\[\]| .]+=[^=]`, prev, 1)
	count(m) > 0
	v := m[0][1]
}

# String literals containing whitespace are prose, not keys.
_strip(line) := regex.replace(line, concat("", [`"[^"\n]*\s[^"\n]*"|'[^'\n]*\s[^'\n]*'|`, "`[^`\\n]*`"]), `""`)

_targets := `amount|unit_amount|amount_total|total|subtotal|grand_total|total_price|discount|balance`

# Object shorthand: stripe.charges.create({ amount, currency }) passes the
# variable named amount.
_sink_rhs(line) := m[1] if {
	some m in regex.find_all_string_submatch_n(concat("", [`[\{,]\s*(`, _targets, `)\s*[,}]`]), line, -1)
}

# Each sink form yields the right-hand side that must carry the client value.
_sink_rhs(line) := rhs if {
	m := regex.find_all_string_submatch_n(concat("", [`[\(\{,]\s*['"]?(?:`, _targets, `)['"]?\s*[:=]\s*([^,}=][^,}]*)`]), line, -1)
	some mm in m
	rhs := mm[1]
}

_sink_rhs(line) := rhs if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*['"]?(?:`, _targets, `)['"]?\s*:\s*([^,}]+)`]), line, 1)
	count(m) > 0
	rhs := m[0][1]
}

_sink_rhs(line) := rhs if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:`, _targets, `)\s*=\s*([^=].*),\s*$`]), line, 1)
	count(m) > 0
	rhs := m[0][1]
}

_sink_rhs(line) := rhs if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:\.|\[\s*['"])(?:`, _targets, `)['"]?\]?\s*(?:[-+]=|=)\s*([^=].*)$`]), line, 1)
	count(m) > 0
	not regex.match(`^\s*(?:res|resp|response|ctx)\.`, line)
	rhs := m[0][1]
}

_sink_rhs(line) := rhs if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const\s+|let\s+|var\s+)?(?:`, _targets, `)\s*(?::\s*\w+\s*)?=\s*([^=].*)$`]), line, 1)
	count(m) > 0
	rhs := m[0][1]
	regex.match(`[\w\)\]]\s*[-+*/]\s*[\w\(]`, rhs)
}

_carries(lang, rhs, _, _, _) if _money_source(lang, rhs)

_carries(lang, rhs, lines, i, _) if {
	some v in _tainted(lang, lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), rhs)
	not _guarded(lines, i, v)
}

# The client value is compared or range-checked in an if before use.
_guarded(lines, i, v) if {
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	regex.match(`^\s*(?:\}\s*else\s+)?(?:if|elif|unless)\b|\bassert\b`, l)
	regex.match(concat("", [`\b`, v, `\b\s*(?:[<>]=?|[!=]==?)|(?:[<>]=?|[!=]==?)\s*(?:\w+\()?`, v, `\b`]), l)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	regex.match(`(?i)price|amount|total|discount|cost|fee|balance`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`(?i)amount|total|discount|balance`, raw)
	not helpers.is_comment_line(raw)
	line := _strip(raw)
	some rhs in {r | r := _sink_rhs(line)}
	not regex.match(`^\s*\{|\$(?:gte?|lte?|eq|ne|in)\b`, rhs)
	_carries(lang, rhs, lines, i, line)
	regex.match(`(?i)stripe|paypal|braintree|adyen|square|razorpay|mollie|charge|payment|pay\b|checkout|order|invoice|refund|transfer|wallet|account|cart|basket|price|coupon`, helpers.code_window(lines, i, 10, 0))
	finding := {
		"rule_id": metadata.id,
		"message": "A monetary value taken from the request decides what is charged, credited or booked. The client can set its own price, discount or a negative amount. Compute the amount on the server from the order and catalogue, or reject a client value that does not match",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}
