package vulnetix.rules.vnx_node_022

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-022",
	"name": "Shell injection via shelljs exec()",
	"description": "shelljs exec(), which hands its whole command string to /bin/sh, is called with a command that carries request data, so shell metacharacters in that data run commands of the caller's choosing. Reported, in JavaScript and TypeScript: exec() called through a name bound to shelljs (require, default or namespace import) or through exec imported from it by name (including an `as` alias), whose command argument (on the line or the next two) contains an Express/Koa/Lambda request value (req.query/body/params/headers/cookies, ctx.request/query/params, event.body/queryStringParameters/pathParameters/headers) directly, or a variable assigned from one within the previous 15 lines, or a variable built from such a variable. Not reported: a constant command or one built only from program data (package.json version in a release script), other shelljs commands (ls, rm, cp take paths, not a command line), RegExp.prototype.exec and other objects' exec methods, child_process (VNX-NODE-003), comments and string literals. Use child_process.execFile() with an argument array, and validate the value against an allowlist.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-022/",
	"languages": ["javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["command-injection", "shelljs", "rce", "node"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_mod := `['"]shelljs['"]`

_alias_res := [
	concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*`, _mod, `\s*\)`]),
	concat("", [`\bimport\s+(?:\*\s+as\s+)?(\w+)\s*(?:,\s*\{[^}]*\}\s*)?from\s+`, _mod]),
	concat("", [`\bimport\s+(\w+)\s*=\s*require\(\s*`, _mod]),
]

_named_res := [
	concat("", [`\bimport\s*(?:\w+\s*,\s*)?\{([^}]*)\}\s*from\s*`, _mod]),
	concat("", [`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*`, _mod]),
]

_source := `\b(?:req|request)\.(?:body|query|params|headers|cookies|url|originalUrl|path)\b|\bctx\.(?:request|query|params)\b|\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b`

# Single- and double-quoted literals hold no code; template literals keep
# their ${...} interpolation.
_strip(line) := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, `""`)

_aliases(lines) := {a |
	some l in lines
	contains(l, "shelljs")
	not helpers.is_comment_line(l)
	some re in _alias_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	a := m[1]
}

_named(lines) := {local |
	some l in lines
	contains(l, "shelljs")
	not helpers.is_comment_line(l)
	some re in _named_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	some item in split(m[1], ",")
	parts := regex.split(`\s+as\s+|\s*:\s*`, trim_space(item))
	parts[0] == "exec"
	local := trim_space(parts[count(parts) - 1])
}

_sink_re(aliases, named) := concat("|", array.concat(
	[concat("", [`\b`, a, `\s*\.\s*exec\s*\(`]) | some a in aliases],
	[concat("", [`(?:^|[^.\w])`, n, `\s*\(`]) | some n in named],
))

# The command text: the rest of the call's line, and the next two lines
# when the call continues.
_arg(lines, i, re) := arg if {
	code := _strip(lines[i])
	parts := regex.split(re, code)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	arg := _continued(lines, i, rest)
}

_continued(_, _, rest) := rest if contains(rest, ")")

_continued(lines, i, rest) := concat(" ", array.concat([rest], next)) if {
	not contains(rest, ")")
	next := [_strip(lines[j]) | some j in numbers.range(i + 1, min([i + 2, count(lines) - 1]))]
}

_tainted(lines, i) := t1 | t2 if {
	t1 := helpers.tainted_names(lines, i, 15, _source)
	t2 := {v |
		some j in numbers.range(max([0, i - 15]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		some t in t1
		regex.match(concat("", [`\b`, t, `\b`]), l)
		v := helpers.assigned_first(l)
		not v in t1
	}
}

_reaches(_, _, arg) if regex.match(_source, arg)

_reaches(lines, i, arg) if {
	some v in _tainted(lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), arg)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	contains(content, "shelljs")
	contains(content, "exec")
	lines := split(content, "\n")
	re := _sink_re(_aliases(lines), _named(lines))
	re != ""
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	regex.match(re, _strip(line))
	arg := _arg(lines, i, re)
	_reaches(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "shelljs exec() runs its command through /bin/sh and this command carries request data; an attacker can append shell commands. Use child_process.execFile() with an argument array and an allowlisted value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
