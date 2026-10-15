# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_925

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-925",
	"name": "Broadcast receiver acts on an intent without verifying its action or sender",
	"description": "An Android BroadcastReceiver.onReceive(Context, Intent) (a named or anonymous receiver, Java or Kotlin) reads data from the intent it was handed (getStringExtra and the other get*Extra calls, getExtras/extras, getData/data, getDataString) without ever checking which action it carries (getAction()/intent.action, hasAction, on a line that is not only a log statement: Log.d(TAG, \"got \" + intent.getAction()) checks nothing) or who sent it (getSentFromPackage/getSentFromUid), so any app that can reach the receiver can forge the broadcast and drive it with its own values (CWE-925). Reported on the onReceive declaration. Not reported: receivers that check the action or the sender, receivers that never read the intent's data, an onReceive whose second parameter is not an Intent, test files, comments and string literals. The receiver's manifest export and permission are not read here (exported receivers are VNX-926); a receiver protected by a signature permission or registered RECEIVER_NOT_EXPORTED or through LocalBroadcastManager is a false positive to suppress.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-925/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [925],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["android", "broadcast-receiver", "intent-verification", "cwe-925"],
}

# The Intent parameter of onReceive, Java (`Intent intent`) or Kotlin
# (`intent: Intent?`).
_param_res := [
	`\bonReceive\s*\(\s*(?:final\s+)?(?:@\w+\s+)?[\w\.]*Context\s+\w+\s*,\s*(?:final\s+)?(?:@\w+\s+)?(?:android\.content\.)?Intent\s+(\w+)\s*\)`,
	`\bonReceive\s*\(\s*\w+\s*:\s*[\w\.]*Context\??\s*,\s*(\w+)\s*:\s*(?:android\.content\.)?Intent\??\s*\)`,
]

_intent_param(decl) := p if {
	some re in _param_res
	m := regex.find_all_string_submatch_n(re, decl, 1)
	count(m) > 0
	p := m[0][1]
}

_indent(line) := count(regex.find_n(`^[ \t]*`, line, 1)[0])

# Index of the line that closes the method: the first later line starting
# with `}` at the declaration's indentation or less, at most 80 lines on.
_body_end(lines, i) := e if {
	ind := _indent(lines[i])
	last := min([count(lines) - 1, i + 80])
	ends := [j |
		some j in numbers.range(i + 1, last)
		regex.match(`^\s*\}`, lines[j])
		_indent(lines[j]) <= ind
	]
	e := _first_or(ends, last)
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_code(line) := "" if helpers.is_comment_line(line)

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`) if not helpers.is_comment_line(line)

_reads_data(body, p) if regex.match(concat("", [`\b`, p, `\s*\??!?!?\.\s*(?:get\w*Extras?|getData(?:String)?|getClipData)\s*\(|\b`, p, `\s*\??!?!?\.\s*(?:extras|data|dataString|clipData)\b`]), body)

# The action or sender read on a line that is not only a log statement:
# Log.d(TAG, "got " + intent.getAction()) prints the action, it checks nothing.
_verifies(body, p) if {
	re := concat("", [`\b`, p, `\s*\??!?!?\.\s*(?:getAction\s*\(|action\b|hasAction\s*\(|getSentFrom\w*\s*\(|sentFrom\w*\b)`])
	regex.match(re, body)
	some l in split(body, "\n")
	regex.match(re, l)
	not regex.match(`^\s*(?:(?:android\.util\.)?Log\.[a-z]+|Timber\.[a-z]+|(?:log|logger|LOG|LOGGER)\.\w+|System\.(?:out|err)\.print\w*|println|print)\s*\(`, l)
}

# A sender check made on the receiver itself (API 34+).
_verifies(body, _) if regex.match(`\b(?:getSentFromPackage|getSentFromUid|sentFromPackage|sentFromUid)\b`, body)

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	not helpers.is_test_path(path)
	contains(content, "onReceive")
	contains(content, "BroadcastReceiver")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "onReceive")
	not helpers.is_comment_line(line)
	regex.match(`^\s*(?:@Override\s+)?(?:public\s+|override\s+|final\s+)*(?:void\s+|fun\s+)onReceive\s*\(`, line)
	decl := concat(" ", array.slice(lines, i, i + 3))
	p := _intent_param(decl)
	e := _body_end(lines, i)
	body := concat("\n", [_code(l) | some l in array.slice(lines, i, e + 1)])
	_reads_data(body, p)
	not _verifies(body, p)
	finding := {
		"rule_id": metadata.id,
		"message": "This broadcast receiver reads data from the intent without checking its action or sender, so any app that can reach it can forge the broadcast. Verify intent.getAction() (and the sender, or protect the receiver with a signature permission / RECEIVER_NOT_EXPORTED) before acting on it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
