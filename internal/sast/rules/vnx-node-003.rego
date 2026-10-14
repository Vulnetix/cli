package vulnetix.rules.vnx_node_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-003",
	"name": "Command injection via child_process",
	"description": "child_process exec()/execSync() (which run their command through /bin/sh) called with a command built at run time: a template literal with ${...} interpolation, string concatenation, or a variable assigned within the previous 10 lines from such a string or from a request/argv value (req.query/body/params, ctx.request, process.argv). The call must resolve to child_process: a module bound by require/import (cp.exec, child_process.execSync, require('child_process').exec), a destructured or aliased import ({ exec }, { execSync as run }), or a util.promisify(exec) wrapper. Not reported: RegExp.prototype.exec and any other object's exec method (db.exec, re.exec), execFile/spawn with an argument array, constant command strings, and the pattern inside comments or string literals. spawn with shell:true is VNX-NODE-026 and shelljs is VNX-NODE-022.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-003/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "dangerous-function"],
}

_is_js(path) if regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$`, path)

_mod := `['"](?:node:)?child_process['"]`

# A template literal with interpolation becomes the identifier TPLX; every
# other string literal collapses to "".
_strip(line) := regex.replace(
	regex.replace(line, `\x60(?:[^\x60\\]|\\.)*\$\{(?:[^\x60\\]|\\.)*\x60`, "TPLX"),
	`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60`, `""`,
)

# Names the module object is bound to.
_module_names(content) := {m[1] |
	some re in [
		concat("", [`(?:const|let|var|import)\s+(\w+)\s*=\s*require\(\s*`, _mod, `\s*\)`]),
		concat("", [`import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+`, _mod]),
	]
	some m in regex.find_all_string_submatch_n(re, content, -1)
}

# Function names bound to exec/execSync by destructuring or named import.
_fn_destructured(content) := {n |
	some re in [
		concat("", [`\{([^}]*)\}\s*=\s*require\(\s*`, _mod]),
		concat("", [`import\s*\{([^}]*)\}\s*from\s*`, _mod]),
	]
	some m in regex.find_all_string_submatch_n(re, content, -1)
	some item in split(m[1], ",")
	p := regex.find_all_string_submatch_n(`^\s*(exec|execSync)\s*(?:(?::|as)\s*(\w+))?\s*$`, item, 1)
	count(p) > 0
	n := _bound(p[0])
}

_fn_member(content) := {m[1] |
	re := concat("", [`(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*`, _mod, `\s*\)\.(?:exec|execSync)\b`])
	some m in regex.find_all_string_submatch_n(re, content, -1)
}

_bound(p) := p[2] if p[2] != ""

_bound(p) := p[1] if p[2] == ""

# promisify(exec) / util.promisify(cp.exec) wrappers.
_promisified(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(\w+)\s*=\s*(?:\w+\.)?promisify\(\s*(?:\w+\.)?exec\s*\)`, content, -1)
}

_alt(names) := concat("|", sort([n | some n in names]))

_sink_res(content) := res if {
	mods := _module_names(content)
	fns := (_fn_destructured(content) | _fn_member(content)) | _promisified(content)
	res := array.concat(
		array.concat(
			[concat("", [`(?:^|[^\w$.])(?:`, _alt(mods), `)\.(?:exec|execSync)\s*\((.*)$`]) | count(mods) > 0],
			[concat("", [`(?:^|[^\w$.])(?:`, _alt(fns), `)\s*\((.*)$`]) | count(fns) > 0],
		),
		[`require\(\s*""\s*\)\.(?:exec|execSync)\s*\((.*)$`],
	)
}

_source_re := `TPLX|""\s*\+|\+\s*""|\breq\.(?:query|body|params|headers|cookies)|\bctx\.request|\bprocess\.argv`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	contains(content, "child_process")
	lines := split(content, "\n")
	res := _sink_res(content)
	some i, line in lines
	contains(line, "(")
	count(line) <= 400
	not helpers.is_comment_line(line)
	s := _strip(line)
	some re in res
	m := regex.find_all_string_submatch_n(re, s, 1)
	count(m) > 0
	head := regex.replace(_arg(lines, i, m[0][1]), `,.*$`, "")
	_built(lines, i, head)
	finding := {
		"rule_id": metadata.id,
		"message": "child_process exec/execSync runs a command string built at run time through the shell; pass the program and its arguments separately to execFile()/spawn() instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := _strip(lines[i + 1]) if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# The command is interpolated or concatenated in the call itself.
_built(_, _, head) if regex.match(`TPLX|\+`, head)

# The command is a variable assigned from a built string or a request value.
_built(lines, i, head) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$]*)\s*\)?\s*$`, head, 1)
	count(m) > 0
	v := m[0][1]
	stripped := [_strip(l) | some l in array.slice(lines, max([0, i - 10]), i)]
	v in helpers.tainted_names(stripped, count(stripped), 10, _source_re)
}
