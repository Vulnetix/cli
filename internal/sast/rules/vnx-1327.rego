# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1327

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1327",
	"name": "Binding to an Unrestricted IP Address",
	"description": "A server socket is bound to a hard-coded wildcard address (0.0.0.0, ::, [::], or Python's empty host ''), so it accepts connections on every network interface, including public ones the service was never meant to face. Reported: Python socket.bind/create_server/HTTPServer/make_server/wsgi Server with a wildcard address tuple or argument, a gunicorn-style module-level bind = \"0.0.0.0:port\" setting, and host='0.0.0.0' passed to app.run, uvicorn.run, web.run_app, waitress serve and similar server calls; Node .listen(port, '0.0.0.0'), .bind(port, '::') and { host: '0.0.0.0' } listen options; Go net.Listen/ListenPacket, http.ListenAndServe[TLS], framework Listen/Run and http.Server{Addr:} with a \"0.0.0.0:port\" or \"[::]:port\" address; and the same through a constant or variable assigned the wildcard a few lines above. Not reported: loopback and named hosts, an address read from configuration or the environment (even with a wildcard default), Go's \":port\" form (the language default, used by nearly every server, which would bury the deliberate wildcards), CIDR strings and IP comparisons, comments, strings that are not a bind argument, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1327/",
	"languages": ["go", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1327],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["binding-to-unrestricted-ip-addr", "network", "exposure", "cwe-1327"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

_wild := `(?:0\.0\.0\.0|::|\[::\])`

# A quoted wildcard literal (Python's empty host counts only inside an address tuple).
_q_wild := concat("", [`['"]`, _wild, `['"]`])

# A name assigned exactly a wildcard literal (Go: wildcard host:port).
_wild_assign := {
	"python": concat("", [`^\s*([A-Za-z_]\w*)\s*(?::\s*str\s*)?=\s*`, _q_wild, `\s*$`]),
	"node": concat("", [`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*`, _q_wild, `\s*;?\s*$`]),
	"go": `^\s*(?:var\s+|const\s+)?([A-Za-z_]\w*)\s*(?:string\s*)?:?=\s*"(?:0\.0\.0\.0|\[::\]):\d*"\s*$`,
}

# Direct sinks: the wildcard literal is the bind argument on this line.
_direct := {
	"python": [
		concat("", [`\(\s*\(\s*`, _q_wild, `\s*,`]),
		`(?:\.bind|Server|create_server)\s*\(\s*\(\s*(?:''|"")\s*,`,
		concat("", [`\b(?:make_server|start_server|create_server|serve)\s*\([^)]*?`, _q_wild]),
		concat("", [`\b(?:host|address)\s*=\s*`, _q_wild]),
		`^bind\s*=\s*\[?\s*['"](?:0\.0\.0\.0|\[::\]):\d+['"]`,
	],
	"node": [
		concat("", [`\.(?:listen|bind)\s*\(\s*[^,()]+,\s*`, _q_wild]),
		concat("", [`\bhost(?:name)?\s*:\s*`, _q_wild]),
	],
	"go": [
		`\b(?:Listen\w*|Run\w*|Serve\w*|Start\w*)\s*\(\s*(?:"\w+"\s*,\s*)?(?:fmt\.Sprintf\(\s*)?"(?:0\.0\.0\.0|\[::\]):(?:\d*|%[dsv])"`,
		`\bAddr\s*:\s*(?:fmt\.Sprintf\(\s*)?"(?:0\.0\.0\.0|\[::\]):(?:\d*|%[dsv])"`,
	],
}

# A keyword or property sink must sit in a server call: the line itself or one
# of the five above opens one.
_needs_call(lang, l) if {
	lang != "go"
	regex.match(`\b(?:host(?:name)?|address)\s*[:=]`, l)
}

_server_call := `(?:\brun\w*|\bserve\w*|\blisten\w*|Server|\bstart\w*|Config)\s*\(`

_in_server_call(lines, i) if {
	some j in numbers.range(max([0, i - 5]), i)
	regex.match(_server_call, lines[j])
}

_sink_direct(lang, lines, i, line) if {
	some re in _direct[lang]
	regex.match(re, line)
	not _needs_call(lang, line)
}

_sink_direct(lang, lines, i, line) if {
	some re in _direct[lang]
	regex.match(re, line)
	_needs_call(lang, line)
	_in_server_call(lines, i)
}

# Sinks that consume a name assigned the wildcard.
_var_sink("python", v) := concat("", [`\bhost\s*=\s*`, v, `\b|\(\s*\(\s*`, v, `\s*,|\b(?:make_server|start_server|create_server|serve)\s*\(\s*`, v, `\s*,`])

_var_sink("node", v) := concat("", [`\.(?:listen|bind)\s*\(\s*[^,()]+,\s*`, v, `\b|\bhost(?:name)?\s*:\s*`, v, `\b`])

_var_sink("go", v) := concat("", [`\b(?:Listen\w*|Run\w*|Serve\w*)\s*\(\s*(?:"\w+"\s*,\s*)?`, v, `\s*[,)]|\bAddr\s*:\s*`, v, `\b`])

_sink_var(lang, lines, i, line, wild_vars) if {
	some [j, v] in wild_vars
	j < i
	contains(line, v)
	regex.match(_var_sink(lang, v), line)
}

_strip_comment("python", l) := regex.replace(l, `\s#.*$`, "")

_strip_comment(lang, l) := regex.replace(l, `\s//.*$`, "") if lang != "python"

_hint := ["0.0.0.0", "[::]", "\"::\"", "'::'"]

_gate(content) if {
	some h in _hint
	contains(content, h)
}

_gate(content) if regex.match(`(?:\.bind|Server|create_server)\s*\(\s*\(\s*(?:''|"")\s*,`, content)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	_gate(content)
	lines := split(content, "\n")
	wild_vars := {[j, v] |
		some j, l in lines
		contains(l, "=")
		_has_wild(l)
		m := regex.find_all_string_submatch_n(_wild_assign[lang], l, 1)
		count(m) > 0
		v := m[0][1]
	}
	some i, raw in lines
	_candidate(raw, wild_vars)
	not helpers.is_comment_line(raw)
	line := _strip_comment(lang, raw)
	_sink(lang, lines, i, line, wild_vars)
	finding := {
		"rule_id": metadata.id,
		"message": "Server binds to a wildcard address (0.0.0.0 / ::), accepting connections on every interface; bind to 127.0.0.1 or a specific interface, or take the address from configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

_candidate(l, _) if contains(l, "0.0.0.0")

_candidate(l, _) if contains(l, "::")

_candidate(l, _) if contains(l, "''")

_candidate(l, _) if contains(l, "\"\"")

_candidate(l, wild_vars) if {
	count(wild_vars) > 0
	some [_, v] in wild_vars
	contains(l, v)
}

_sink(lang, lines, i, line, _) if _sink_direct(lang, lines, i, line)

_sink(lang, lines, i, line, wild_vars) if _sink_var(lang, lines, i, line, wild_vars)

_has_wild(l) if contains(l, "0.0.0.0")

_has_wild(l) if contains(l, "::")
