# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1027

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1027",
	"name": "Request data in a require() or import() module specifier (Node.js)",
	"description": "An injection (OWASP Top Ten 2017 A1, CWE-1027) in Node.js where the module the process loads is chosen by the request: the specifier of require(), require.resolve() or dynamic import() contains Express/Koa request data (req/request .query/.body/.params/.headers/.cookies, ctx.query/ctx.params/ctx.request.body), directly, through a variable assigned or destructured from it a few lines above, or concatenated/interpolated into a path. A caller can then load any module or JavaScript file the process can read (../../ traversal, an uploaded file), which runs with the server's privileges. Not reported: constant specifiers, a lookup through an object or Map (require(PLUGINS[name])), a value checked against an allowlist (includes/has/indexOf/switch) in the lines between, comments and test files. Other A1 injection classes have their own rules: eval/Function/vm (VNX-913, VNX-94), child_process (VNX-NODE-003), SQL (VNX-NODE-007), NoSQL (VNX-NODE-014), templates (VNX-NODE-011).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1027/",
	"languages": ["node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1027],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["injection", "dynamic-require", "code-injection", "cwe-1027"],
}

_source := `\b(?:req|request)\.(?:query|body|params|headers|cookies|param\()|\bctx\.(?:query|params|request\.(?:body|query))\b`

_ext(path) if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx)$`, path)

_sink := `(?:^|[^\w.$])(?:require(?:\.resolve)?|import)\s*\((.*)$`

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	not helpers.is_test_path(path)
	regex.match(`\b(?:require|import)\s*\(`, content)
	regex.match(_source, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(_sink, line, 1)
	count(m) > 0
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w.$])(?:require(?:\.resolve)?|import)\s*\(`, _strip(line))
	arg := _arg_text(lines, i, m[0][1])
	not regex.match(`^\s*(?:"[^"]*"|'[^']*'|\x60[^\x60$]*\x60)\s*\)`, arg)
	not regex.match(`^\s*[\w$.]+\s*\[`, arg)
	_tainted(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Module specifier built from request data: a caller chooses which file require()/import() loads and runs (path traversal to any .js file, an uploaded file). Map the request value through a fixed table of allowed modules",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_tainted(_, _, arg) if regex.match(_source, arg)

_tainted(lines, i, arg) if {
	some v in _names(lines, i)
	regex.match(concat("", [`(?:^|[^\w$.])`, v, `\b`]), arg)
	not _guarded(lines, i, v)
}

_names(lines, i) := helpers.tainted_names(lines, i, 12, _source) | _destructured(lines, i)

_destructured(lines, i) := {trim_space(n) |
	i > 0
	some j in numbers.range(max([0, i - 12]), i - 1)
	not helpers.is_comment_line(lines[j])
	some m in regex.find_all_string_submatch_n(concat("", [`\{([^{}]*)\}\s*=\s*(?:`, _source, `)`]), lines[j], -1)
	some part in split(m[1], ",")
	n := regex.replace(regex.replace(part, `^\s*\w+\s*:\s*`, ""), `\s*=.*$`, "")
	regex.match(`^\s*[A-Za-z_$][\w$]*\s*$`, n)
}

_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	regex.match(concat("", [`\.(?:includes|has|indexOf)\(\s*`, v, `\b|\bswitch\s*\(\s*`, v, `\b|\b`, v, `\s*(?:===|!==)\s*["']`]), lines[j])
}

_strip(s) := regex.replace(s, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

# The specifier, continued onto the next two lines when the call is split.
_arg_text(_, _, rest) := rest if contains(rest, ")")

_arg_text(lines, i, rest) := concat(" ", array.concat([rest], [lines[k] | some k in numbers.range(i + 1, min([count(lines) - 1, i + 2]))])) if {
	not contains(rest, ")")
}
