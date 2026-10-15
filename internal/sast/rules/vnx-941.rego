# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_941

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-941",
	"name": "Message sent without specifying its intended recipient",
	"description": "Data is sent over a channel whose destination is left open, so whoever is listening receives it. Reported: in JavaScript/TypeScript (and inline scripts of HTML/Vue pages), postMessage(data, '*') or postMessage(data, { targetOrigin: '*' }) sent to another window (window.opener, parent, top, an iframe's contentWindow, a popup or any other window reference), which delivers the data to whatever origin that window now shows; in Android Java/Kotlin, sendBroadcast/sendOrderedBroadcast/sendStickyBroadcast of an implicit Intent (created with only an action, or no arguments) that carries extras (putExtra) and is sent (on any Context receiver: context, mContext, context?., requireActivity()) without a receiver permission and without setPackage/setComponent/setClass, so any installed app can register for the action and read the extras. Not reported: postMessage with an explicit target origin, postMessage to the page's own window (window.postMessage / self.postMessage / bare postMessage) and Worker/MessagePort postMessage (which take no target origin), explicit Intents (new Intent(ctx, X.class), X::class.java), broadcasts with a permission argument, LocalBroadcastManager, intents without extras, comments and string literals. VNX-NODE-024 also reports the wildcard postMessage shape.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-941/",
	"languages": ["node", "java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [941],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["postmessage", "android", "broadcast", "cwe-941"],
}

# ── JavaScript: postMessage(data, '*') ──────────────────────────────────

_js_ext := `\.(js|jsx|mjs|cjs|ts|tsx|vue|svelte|html|htm)$`

_js_skip(path) if regex.match(`(^|/)node_modules/|\.min\.js$`, path)

# The receiver of a postMessage call that begins on this line.
_pm_receiver(line) := r if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_$][\w$]*(?:!?\s*\??\.\s*[A-Za-z_$][\w$]*|\[[^\]]*\]|\(\s*\))*)!?\s*\??\.\s*postMessage\s*\(`, _strip_strings(line), 1)
	count(m) > 0
	r := regex.replace(m[0][1], `[\s!?]+`, "")
}

# String literals blanked, so a call named inside a message is not a call.
_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\x60[^\x60]*\x60`, `""`)

_own_window := {"window", "self", "globalThis", "this", "worker", "port", "port1", "port2"}

_other_window(r) if {
	not r in _own_window
	not regex.match(`(?i)(worker|port|channel)$`, r)
}

# A local alias of the page's own window (win = win || window), used for
# the zero-timeout self-message idiom.
_self_alias(lines, i, r) if {
	regex.match(`^[A-Za-z_$][\w$]*$`, r)
	re := concat("", [`(^|[^\w$.])`, r, `\s*=\s*(?:[\w$]+\s*\|\|\s*)?(?:window|self|globalThis)\s*;?\s*$`])
	some j in numbers.range(max([0, i - 15]), i - 1)
	contains(lines[j], r)
	regex.match(re, lines[j])
}

# The call's argument text, from postMessage( to its closing ')', within 6 lines.
_call_text(lines, i) := t if {
	last := min([count(lines) - 1, i + 6])
	joined := concat("\n", [l | some k in numbers.range(i, last); l := lines[k]])
	idx := indexof(joined, "postMessage")
	t := substring(joined, idx, -1)
}

_wildcard_target(t) if {
	m := regex.find_all_string_submatch_n(`^postMessage\s*\(([^;]*?),\s*["'\x60]\*["'\x60]\s*(?:,[^;)]*)?\)`, t, 1)
	count(m) > 0
	not contains(m[0][1], "postMessage")
}

# The options form: postMessage(data, { targetOrigin: '*' })
_wildcard_target(t) if {
	m := regex.find_all_string_submatch_n(`^postMessage\s*\(([^;]*?),\s*\{[^};]*\btargetOrigin\s*:\s*["'\x60]\*["'\x60]`, t, 1)
	count(m) > 0
	not contains(m[0][1], "postMessage")
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_js_ext, path)
	not _js_skip(path)
	contains(content, "postMessage")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "postMessage")
	not helpers.is_comment_line(line)
	r := _pm_receiver(line)
	_other_window(r)
	not _self_alias(lines, i, r)
	_wildcard_target(_call_text(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "postMessage(..., '*') sends this data to whatever origin the target window currently shows. Pass the expected origin as the second argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Android: implicit broadcast carrying extras ─────────────────────────

_and_ext := `\.(java|kt)$`

# [receiver (may be empty), intent variable]
_bcast_re := `(?:([\w$]+(?:\(\s*\))?)\s*[?!]?\s*\.\s*|^|[^\w.$])send(?:Ordered|Sticky)?Broadcast\(\s*([A-Za-z_]\w*)\s*(?:,\s*(null)\s*)?\)`

# A receiver that is a LocalBroadcastManager (by name, or declared or
# assigned as one in this file) delivers only inside the app.
_local_receiver(_, r) if regex.match(`(?i)local|^lbm$|^getInstance`, r)

_local_receiver(content, r) if {
	r != ""
	regex.match(concat("", [`\b`, r, `\s*(?::\s*|=\s*)LocalBroadcastManager\b|\bLocalBroadcastManager\s+`, r, `\b`]), content)
}

_intent_decl(line, v) if {
	re := concat("", [`\b`, v, `\s*=\s*(?:new\s+)?Intent\s*\(([^)]*)\)`])
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	not regex.match(`\.class\b|::class`, m[0][1])
}

_targeted(l) if regex.match(`\b(setPackage|setComponent|setClass|setClassName|setSelector)\s*\(|\b(package|component)\s*=\s*[^=]`, l)

_implicit_with_extras(lines, i, v) if {
	start := max([0, i - 30])
	decls := [j | some j in numbers.range(start, i - 1); _intent_decl(lines[j], v); not helpers.is_comment_line(lines[j])]
	count(decls) > 0
	d := max(decls)
	between := [lines[k] | some k in numbers.range(d, i - 1); not helpers.is_comment_line(lines[k])]
	some l in between
	regex.match(`\bputExtras?\s*\(`, l)
	not _any_targeted(between)
}

_any_targeted(ls) if {
	some l in ls
	_targeted(l)
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_and_ext, path)
	contains(content, "Broadcast(")
	contains(content, "putExtra")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Broadcast(")
	not helpers.is_comment_line(line)
	not regex.match(`(?i)localbroadcastmanager|\blbm\b|\blocalBroadcast`, line)
	m := regex.find_all_string_submatch_n(_bcast_re, line, 1)
	count(m) > 0
	not _local_receiver(content, m[0][1])
	_implicit_with_extras(lines, i, m[0][2])
	finding := {
		"rule_id": metadata.id,
		"message": "Implicit broadcast carries extras with no receiver permission and no target package: any installed app can register for the action and read them. Use an explicit Intent (setPackage/setComponent), a receiver permission, or LocalBroadcastManager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
