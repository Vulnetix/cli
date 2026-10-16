# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_927

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-927",
	"name": "Implicit Intent broadcast that any app can receive",
	"description": "Reports an Android broadcast that any installed app can receive (CWE-927) in Java and Kotlin: sendBroadcast(i), sendOrderedBroadcast(i, null[, resultReceiver, ...]) or sendBroadcastAsUser(i, user) with no receiver permission (the call's arguments may start on the next line), where i is built a few lines above as an implicit Intent (new Intent(), new Intent(\"action\") or new Intent(ACTION_CONSTANT), Kotlin Intent(...)) and no setPackage/setComponent/setClass/setClassName (or package/component assignment) makes it explicit before the send; the same call with the implicit Intent built inline; and every sendStickyBroadcast/sendStickyOrderedBroadcast, whose extras any app can read back. Not reported: a broadcast with a permission argument, explicit Intents (new Intent(context, Receiver.class) or one given a package or component), LocalBroadcastManager sends, comments and strings. Intents built in another method or passed in as a parameter are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-927/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [927],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["use-of-implicit-intent", "android", "cwe-927"],
}

_ext(path) if endswith(path, ".java")

_ext(path) if endswith(path, ".kt")

# An Intent constructor that names no target component: no argument, an action
# string, or an action constant.
_implicit_ctor := `(new\s+)?Intent\s*\(\s*("[^"]*"|(?:[\w.]*\.)?[A-Z][A-Z0-9_]+)?\s*\)`

_explicit_re := `\b(setPackage|setComponent|setClass|setClassName|setSelector)\s*\(|(^|[\s.])\x60?(package|component)\x60?\s*=[^=]`

_sticky_re := `\bsendSticky(Ordered)?Broadcast(AsUser)?\s*\(`

_var_send_re := `\b(sendBroadcast|sendOrderedBroadcast)\s*\(\s*([A-Za-z_]\w*)\s*(,\s*null\s*)?\)`

_inline_send_re := concat("", [`\b(sendBroadcast|sendOrderedBroadcast)\s*\(\s*`, _implicit_ctor])

# A permission argument closing the inline call.
_perm_arg_re := `,\s*("[^"]*"|(?i:[\w.]*perm[\w.]*))\s*\)\s*;?\s*$`

_local_names(content, lines) := {v |
	contains(content, "LocalBroadcastManager")
	some l in lines
	contains(l, "LocalBroadcastManager.getInstance")
	v := helpers.assigned_ident(l)
}

_local(line, _) if regex.match(`(?i)localbroadcast`, line)

_local(line, names) if {
	m := regex.find_all_string_submatch_n(`(\w+)\s*\.\s*send\w*Broadcast`, line, 1)
	count(m) > 0
	m[0][1] in names
}

_implicit_var(lines, i, v) if {
	start := max([0, i - 25])
	some j in numbers.range(start, i - 1)
	contains(lines[j], "Intent")
	not helpers.is_comment_line(lines[j])
	regex.match(concat("", [`\b`, v, `\b(\s*:\s*Intent\??)?\s*=\s*`, _implicit_ctor]), _ctor_text(lines, j))
	not _made_explicit(lines, j, i)
	not _redeclared(lines, j, i, v)
}

# A later assignment to the same name (another method's local, or a new Intent)
# replaces the one found, so only the nearest assignment counts.
_redeclared(lines, j, i, v) if {
	some k in helpers.span(j + 1, i - 1)
	not helpers.is_comment_line(lines[k])
	regex.match(concat("", [`(^|[\s(;,])`, v, `\s*(:\s*Intent\??)?\s*=[^=]`]), lines[k])
}

# The assignment, joined with the next line when the constructor's argument starts there.
_ctor_text(lines, j) := lines[j] if not regex.match(`Intent\s*\(\s*$`, lines[j])

_ctor_text(lines, j) := concat(" ", [lines[j], trim_space(lines[j + 1])]) if {
	regex.match(`Intent\s*\(\s*$`, lines[j])
	j + 1 < count(lines)
}

_made_explicit(lines, j, i) if {
	some k in numbers.range(j, i - 1)
	not helpers.is_comment_line(lines[k])
	regex.match(_explicit_re, lines[k])
}

_reason(line, _) := "a sticky broadcast, whose extras any app can read" if regex.match(_sticky_re, line)

_reason(line, lines) := "an implicit Intent with no receiver permission" if not regex.match(_sticky_re, line)

_hit(line, _, _) if regex.match(_sticky_re, line)

_hit(line, _, _) if {
	regex.match(_inline_send_re, line)
	not regex.match(_explicit_re, line)
	not regex.match(_perm_arg_re, line)
}

_hit(line, lines, i) if {
	v := _sent_var(_call_text(line, lines, i))
	_implicit_var(lines, i, v)
}

# The call, joined with the next line when its argument list starts there.
_call_text(line, _, _) := line if not regex.match(`Broadcast\w*\s*\(\s*$`, line)

_call_text(line, lines, i) := concat(" ", [line, trim_space(lines[i + 1])]) if {
	regex.match(`Broadcast\w*\s*\(\s*$`, line)
	i + 1 < count(lines)
}

# sendBroadcast(i) / sendOrderedBroadcast(i, null)
_sent_var(call) := m[0][2] if {
	m := regex.find_all_string_submatch_n(_var_send_re, call, 1)
	count(m) > 0
}

# sendOrderedBroadcast(i, null, resultReceiver, ...)
_sent_var(call) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bsendOrderedBroadcast\s*\(\s*([A-Za-z_]\w*)\s*,\s*null\s*,`, call, 1)
	count(m) > 0
}

# sendBroadcastAsUser(i, user) / sendBroadcastAsUser(i, user, null)
_sent_var(call) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bsendBroadcastAsUser\s*\(\s*([A-Za-z_]\w*)\s*,\s*[\w.]+(\(\s*\))?\s*(,\s*null\s*)?\)`, call, 1)
	count(m) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`send\w*Broadcast`, content)
	lines := split(content, "\n")
	names := _local_names(content, lines)
	some i, line in lines
	contains(line, "Broadcast")
	regex.match(`\bsend\w*Broadcast\w*\s*\(`, line)
	not helpers.is_comment_line(line)
	regex.match(`\bsend\w*Broadcast\w*\s*\(`, regex.replace(line, `"(\\.|[^"\\])*"`, `""`))
	not _local(line, names)
	_hit(line, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Broadcast sent as %s: any installed app can register for it and read its extras. Make the Intent explicit (setPackage/setComponent) or pass a signature-level receiver permission", [_reason(line, lines)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
