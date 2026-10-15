# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_940

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-940",
	"name": "Cross-window message handler does not verify the sender's origin",
	"description": "Browser code accepts window messages without checking who sent them, so any page that frames or opens this one can drive it. Reported, in JavaScript/TypeScript and inline scripts of HTML/Vue pages: a window 'message' listener (window.addEventListener('message', ...), also split after its parenthesis with 'message' and the handler on the following lines, a bare top-level addEventListener('message', ...), window.onmessage = ..., $(window).on('message', ...)) whose handler, inline or a named function or const declared in the same file, never reads the event's origin or source. Not reported: a handler that reads origin (event.origin, a destructured { origin }) or compares event.source; a named handler the file does not define; message events of Workers, WebSockets, MessagePorts, BroadcastChannels, Node child processes and service/web-worker scripts (self.addEventListener); comments and string literals. VNX-NODE-024 reports the same listener shape alongside wildcard postMessage targets.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-940/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [940],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["postmessage", "origin", "cwe-940"],
}

_ext_re := `\.(js|jsx|mjs|cjs|ts|tsx|vue|svelte|html|htm)$`

_skip(path) if regex.match(`(^|/)node_modules/|\.min\.js$|(?i)(^|/)[^/]*(service-?worker|\bsw|worker)[^/]*\.(js|ts|mjs)$`, path)

# A listener on the window for the 'message' event.
_listen_re := `(?:(?:^|[^\w.$])(?:window|globalThis)\s*\.\s*addEventListener|^\s*addEventListener|\$\(\s*window\s*\)\s*\.\s*on)\(\s*["'\x60]message["'\x60]\s*,\s*(.*)$`

_onmessage_re := `(?:^|[^\w.$])(?:window|globalThis)\s*\.\s*onmessage\s*=\s*(.*)$`

_handler_rest(line) := r if {
	m := regex.find_all_string_submatch_n(_listen_re, line, 1)
	count(m) > 0
	r := m[0][1]
}

_handler_rest(line) := r if {
	not regex.match(_listen_re, line)
	m := regex.find_all_string_submatch_n(_onmessage_re, line, 1)
	count(m) > 0
	r := m[0][1]
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The body of a function starting at line i: up to the closing brace at
# the same indentation, bounded at 60 lines.
_body(lines, i) := txt if {
	contains(lines[i], "{")
	not _balanced(lines[i])
	ii := _indent(lines[i])
	last := min([count(lines) - 1, i + 60])
	ends := [j |
		some j in numbers.range(i + 1, last)
		_indent(lines[j]) <= ii
		startswith(trim_space(lines[j]), "}")
	]
	end := min(array.concat([last], ends))
	txt := concat("\n", [l | some k in numbers.range(i, end); l := lines[k]; not helpers.is_comment_line(l)])
}

_body(lines, i) := lines[i] if not contains(lines[i], "{")

_body(lines, i) := lines[i] if {
	contains(lines[i], "{")
	_balanced(lines[i])
}

_balanced(line) if count(regex.find_all_string_submatch_n(`\{`, line, -1)) == count(regex.find_all_string_submatch_n(`\}`, line, -1))

_checks_sender(txt) if regex.match(`\borigin\b|\.source\b`, txt)

# A named handler: window.addEventListener('message', onMessage)
_named(rest) := n if {
	m := regex.find_all_string_submatch_n(`^(?:this\.)?([A-Za-z_$][\w$]*)\s*(?:\)|,)`, trim_space(rest), 1)
	count(m) > 0
	n := m[0][1]
	not n in {"function", "async"}
}

_decl_index(lines, n) := j if {
	re := concat("", [`(?:\bfunction\s+`, n, `\s*\(|\b(?:const|let|var)\s+`, n, `\s*=|^\s*(?:async\s+)?`, n, `\s*\([^)]*\)\s*\{|^\s*`, n, `\s*[:=]\s*(?:async\s*)?(?:function|\())`])
	js := [k | some k, l in lines; contains(l, n); regex.match(re, l); not helpers.is_comment_line(l)]
	count(js) > 0
	j := js[0]
}

# The listener call split after its parenthesis: the event name on the next
# line and the handler after it (or on the line after that).
_open_re := `(?:(?:^|[^\w.$])(?:window|globalThis)\s*\.\s*addEventListener|^\s*addEventListener|\$\(\s*window\s*\)\s*\.\s*on)\(\s*$`

# [handler argument text, line index where the handler starts]
_listener(_, i, line) := [r, i] if {
	contains(line, "message")
	r := _handler_rest(line)
}

_listener(lines, i, line) := x if {
	regex.match(_open_re, line)
	i + 1 < count(lines)
	m := regex.find_all_string_submatch_n(`^\s*["'\x60]message["'\x60]\s*,\s*(.*)$`, lines[i + 1], 1)
	count(m) > 0
	x := _split_rest(lines, i + 1, m[0][1])
}

_split_rest(_, k, r) := [r, k] if not regex.match(`^\s*$`, r)

_split_rest(lines, k, r) := [lines[k + 1], k + 1] if {
	regex.match(`^\s*$`, r)
	k + 1 < count(lines)
}

_unchecked(lines, i, rest) if {
	not _named(rest)
	not _checks_sender(_body(lines, i))
}

_unchecked(lines, _, rest) if {
	n := _named(rest)
	j := _decl_index(lines, n)
	not _checks_sender(_body(lines, j))
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_ext_re, path)
	not _skip(path)
	contains(content, "message")
	regex.match(`(?m)(addEventListener|\.on)\(\s*["'\x60]message["'\x60]|\bonmessage\s*=`, content)
	not regex.match(`(?m)^\s*(importScripts\(|self\.addEventListener\(\s*["'](install|fetch|activate)["'])`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`message|\(\s*$`, line)
	not helpers.is_comment_line(line)
	some [rest, hi] in {_listener(lines, i, line)}
	_unchecked(lines, hi, rest)
	finding := {
		"rule_id": metadata.id,
		"message": "Window 'message' handler never checks event.origin (or event.source): any site that frames or opens this page can send it commands. Compare event.origin against the expected origin before using event.data",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
