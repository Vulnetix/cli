# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_837

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-837",
	"name": "Improper Enforcement of a Single, Unique Action",
	"description": "A Stripe call that moves money (Charge/PaymentIntent/Refund/Transfer/Payout/Topup create in Python, including the StripeClient payment_intents/charges/refunds/transfers/payouts services; stripe.charges/paymentIntents/refunds/transfers/payouts/topups.create in JavaScript/TypeScript, on any receiver named like stripe or bound by new Stripe(...) or require('stripe')(...)) made without an idempotency key. A retried request, a double-submitted form or a replayed webhook then charges, refunds or pays out twice, because nothing makes the action happen once. Not reported: a call whose arguments or the ten lines above it name an idempotency key in code (idempotency_key=, {idempotencyKey: ...}, an options dict built just before; a comment mentioning idempotency does not count), read calls (retrieve, list), creates that do not move money (customers, products), test code, and the call in comments or string literals. Other single-use actions (coupons, votes) have no recognisable API and are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-837/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [837],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-enforcement-of-single-unique-action", "idempotency", "payments", "cwe-837"],
}

_call_re := {
	"py": `\bstripe\.(?:Charge|PaymentIntent|Refund|Transfer|Payout|Topup)\.create\s*\(|\.(?:charges|payment_intents|refunds|transfers|payouts|topups)\.create\s*\(`,
	"js": `\b(?i:[\w\.]*stripe\w*)\.(?:charges|paymentIntents|refunds|transfers|payouts|topups)\.create\s*\(`,
}

_is_call(lang, line, _) if regex.match(_call_re[lang], line)

# A JavaScript client bound to any name: const sc = new Stripe(key) or
# const pay = require('stripe')(key).
_is_call("js", line, content) if {
	some m in regex.find_all_string_submatch_n(`(?:const|let|var)\s+(\w+)\s*=\s*(?:new\s+Stripe\s*\(|require\(\s*['"]stripe['"]\s*\)\s*\()`, content, -1)
	regex.match(concat("", [`\b`, m[1], `\.(?:charges|paymentIntents|refunds|transfers|payouts|topups)\.create\s*\(`]), line)
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_strip(line) := regex.replace(line, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`[^`]*`", "\"\"")

_delta(line) := count(regex.find_all_string_submatch_n(`\(`, line, -1)) - count(regex.find_all_string_submatch_n(`\)`, line, -1))

# The line on which the call opened at i closes its parentheses.
_call_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 20])
	ends := [k |
		some k in numbers.range(i, last)
		sum([_delta(_strip(lines[m])) | some m in numbers.range(i, k)]) <= 0
	]
	e := _first_or(ends, last)
}

_first_or(ends, _) := min(ends) if count(ends) > 0

_first_or(ends, last) := last if count(ends) == 0

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, ".create")
	regex.match(`(?i)stripe`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, ".create")
	not helpers.is_comment_line(raw)
	line := _strip(raw)
	_is_call(lang, line, content)
	e := _call_end(lines, i)
	window := concat("\n", [lines[k] | some k in numbers.range(max([0, i - 10]), e); not helpers.is_comment_line(lines[k])])
	not regex.match(`(?i)idempotency_?key`, window)
	finding := {
		"rule_id": metadata.id,
		"message": "Stripe call that moves money is made without an idempotency key: a retried or double-submitted request performs it twice. Pass idempotency_key / idempotencyKey derived from the order or request id",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}
