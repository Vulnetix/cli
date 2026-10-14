package vulnetix.rules.vnx_node_015

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-015",
	"name": "WebSocket server without origin verification (CSWSH)",
	"description": "A WebSocket server accepts connections from any origin. Reported: a ws server (new WebSocket.Server(...), new ws.Server(...), new WebSocketServer(...) in a file that imports ws) whose options carry no verifyClient callback, in a file whose code never reads the Origin header (no verifyClient, origin or headers.origin check anywhere, for example in an upgrade handler); and a Socket.IO server whose options (within the eight lines after new Server(...), io(...) or require('socket.io')(...)) set cors origin to '*' or true, or the v2 origins: '*:*', without an allowRequest callback. Browsers send cookies on a cross-site WebSocket handshake, so without an origin check a malicious page can open an authenticated socket in the victim's name (Cross-Site WebSocket Hijacking). Not reported: servers with verifyClient or an origin check in the same file, Socket.IO servers with a list of origins, Express cors({ origin: '*' }) middleware, browser WebSocket clients, test files, comments and string literals. An origin check in another file (shared middleware, a reverse proxy) is not seen.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-015/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1385],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["websocket", "cswsh", "origin-validation"],
}

_is_js(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_blank(s) := regex.replace(s, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, "''")

_imports_ws(content) if regex.match(`require\(\s*['"]ws['"]\s*\)|from\s+['"]ws['"]`, content)

_imports_socketio(content) if regex.match(`require\(\s*['"]socket\.io['"]\s*\)|from\s+['"]socket\.io['"]`, content)

_ws_ctor := `\bnew\s+(?:(?:WebSocket|ws|WS|wsModule)\.Server|WebSocketServer)\s*\(`

# The ws server's own options, up to eight further lines.
_window(lines, i, n) := concat("\n", array.slice(lines, i, min([count(lines), i + n + 1])))

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not helpers.is_test_path(path)
	regex.match(`WebSocket\.Server|WebSocketServer|\.Server\s*\(`, content)
	_imports_ws(content)
	lines := split(content, "\n")
	code := helpers.code_text(lines)
	not regex.match(`verifyClient|\borigin\b`, code)
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_ws_ctor, _blank(line))
	finding := _finding(path, i, line, "WebSocket server accepts any Origin: a malicious page can open a socket with the victim's cookies (CSWSH). Add a verifyClient callback (or check req.headers.origin on upgrade) that accepts only trusted origins")
}

# Socket.IO: the server's options allow every origin.
_io_ctor := `\bnew\s+[\w$]*Server\s*\(|\bsocket\.io['"]\s*\)\s*\(|(?:^|[^\w$.])(?:io|socketIo|socketIO|SocketIO)\s*\(\s*[\w$]+\s*,`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not helpers.is_test_path(path)
	contains(content, "origin")
	_imports_socketio(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`\borigins?\s*:\s*(?:'\*(?::\*)?'|"\*(?::\*)?"|true\b)`, line)
	not regex.match(`\bcors\s*\(\s*\{`, line)
	some k in numbers.range(max([0, i - 8]), i)
	regex.match(_io_ctor, lines[k])
	not regex.match(`\bcors\s*\(`, lines[k])
	not contains(_window(lines, k, 12), "allowRequest")
	finding := _finding(path, i, line, "Socket.IO server accepts any Origin: a malicious page can open a socket with the victim's cookies (CSWSH). List the trusted origins in cors.origin, or check the origin in allowRequest")
}
