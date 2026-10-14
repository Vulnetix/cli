package vulnetix.rules.vnx_node_024

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-024",
	"name": "postMessage without origin validation (CSWSH/XSS)",
	"description": "Browser code trusts cross-window messages without knowing who sent them, or sends data to a window without saying who may read it. Reported, in JavaScript, TypeScript and inline scripts of HTML/Vue pages: a window 'message' listener (window.addEventListener('message', ...), window.onmessage = ..., $(window).on('message', ...)) whose handler body, inline or a named function defined in the same file, never reads event.origin (or compares event.source), so any page that frames or opens this one can drive it; and postMessage(data, '*') to another window (window.opener, parent, top, an iframe's contentWindow, a window reference), which delivers the data to whatever origin that window has navigated to. Not reported: a handler that checks origin or source, a named handler the file does not define, Worker/WebSocket/MessagePort/process 'message' events, service-worker and worker self listeners, window.postMessage(..., '*') to the page's own window, postMessage with an explicit target origin, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-024/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [345],
	"capec": ["CAPEC-111"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["postmessage", "origin-validation", "xss", "browser", "node"],
}

_is_web(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts|html|htm|vue|svelte)$`, path)

# The 'message' event name and a '*' target survive as markers; every other
# string literal is emptied so code written inside one is not code.
_norm(line) := regex.replace(
	regex.replace(
		regex.replace(line, "['\"`]message['\"`]", "__MSG__"),
		"['\"`]\\*['\"`]", "__STAR__",
	),
	"'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`,
)

_listener_re := `\bwindow\s*\.\s*addEventListener\s*\(\s*__MSG__|\bwindow\s*\.\s*onmessage\s*=|\$\(\s*window\s*\)\s*\.\s*on\s*\(\s*__MSG__`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The handler's body: from the listener line to the line that closes it at
# the listener's indentation, at most 40 lines.
_body_end(lines, i) := e if {
	cap := min([i + 40, count(lines) - 1])
	ii := _indent(lines[i])
	ends := [k |
		some k in numbers.range(i + 1, cap)
		_indent(lines[k]) <= ii
		regex.match(`^\s*[})\]]`, lines[k])
	]
	e := min(array.concat([cap], ends))
}

_checks_sender(txt) if regex.match(`\borigin\b|\.source\b`, txt)

_inline_handler(code) if regex.match(`__MSG__\s*,\s*(?:async\s+)?(?:function\b|\(?[\w\s,{}:<>]*\)?\s*=>)|\bonmessage\s*=\s*(?:async\s+)?(?:function\b|\(?[\w\s,{}:<>]*\)?\s*=>)`, code)

_handler_name(code) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`__MSG__\s*,\s*([A-Za-z_$][\w$.]*)\s*[,)]`, code, 1)
	count(m) > 0
}

_handler_name(code) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bonmessage\s*=\s*([A-Za-z_$][\w$.]*)\s*;?\s*$`, code, 1)
	count(m) > 0
}

_unchecked(lines, i, code) if {
	_inline_handler(code)
	body := helpers.code_window(lines, i, 0, _body_end(lines, i) - i)
	not _checks_sender(body)
}

_unchecked(lines, _, code) if {
	not _inline_handler(code)
	full := _handler_name(code)
	parts := split(full, ".")
	name := parts[count(parts) - 1]
	def_re := concat("", [`(?:\bfunction\s+`, name, `\s*\(|\b`, name, `\s*[:=]\s*(?:async\s+)?(?:function\b|\(?[\w\s,{}:<>]*\)?\s*=>)|^\s*(?:async\s+)?`, name, `\s*\([^)]*\)\s*\{)`])
	some d, l in lines
	contains(l, name)
	regex.match(def_re, l)
	not helpers.is_comment_line(l)
	body := helpers.code_window(lines, d, 0, _body_end(lines, d) - d)
	not _checks_sender(body)
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

findings contains f if {
	some path, content in input.file_contents
	_is_web(path)
	not endswith(path, ".min.js")
	contains(content, "window")
	regex.match("addEventListener\\s*\\(\\s*['\"`]message|\\bonmessage\\s*=|\\.on\\s*\\(\\s*['\"`]message", content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "window")
	regex.match(`\bwindow\s*\.\s*(?:addEventListener|onmessage)|\$\(\s*window\s*\)`, line)
	not helpers.is_comment_line(line)
	code := _norm(line)
	regex.match(_listener_re, code)
	_unchecked(lines, i, code)
	f := _finding(path, i, line, "This window 'message' handler never checks event.origin: any page that frames or opens this one can send it data. Compare event.origin with an allowlist before using event.data")
}

findings contains f if {
	some path, content in input.file_contents
	_is_web(path)
	not endswith(path, ".min.js")
	contains(content, "postMessage")
	regex.match("['\"`]\\*['\"`]", content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "postMessage")
	not helpers.is_comment_line(line)
	code := _norm(line)
	regex.match(`[\w$\])]\s*\.\s*postMessage\s*\(`, code)
	not regex.match(`(?:^|[^\w.$])(?:window|self|globalThis)\s*\.\s*postMessage\s*\(`, code)
	win := _norm(helpers.code_window(lines, i, 0, 3))
	regex.match(`\.\s*postMessage\s*\((?:[^;]|\n)*?,\s*__STAR__\s*[,)]`, win)
	f := _finding(path, i, line, "postMessage() to another window with target origin '*' delivers the data to whatever site that window now shows; pass the expected origin instead")
}
