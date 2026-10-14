package vulnetix.rules.vnx_node_013

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-013",
	"name": "Node.js command injection via child_process",
	"description": "An OS command run through a shell is built from the incoming request: the command string (first argument) of child_process exec/execSync (called on a module bound by require/import such as cp.exec or child_process.execSync, on require('child_process') directly, as a destructured { exec }/{ execSync } import, or through a util.promisify(exec) wrapper), of spawn/spawnSync/execFile/execFileSync with shell: true, of shelljs exec or execa's command/execaCommand, or the script of spawn('sh'|'bash', ['-c', script]), is a req/request query, body, params, headers or cookies value, a Koa ctx.query/ctx.request.body value, or a variable assigned (or destructured) from one in the 25 lines above, directly or through one intermediate assignment such as 'ls ' + dir. Not reported: execFile/spawn with an argument array and no shell (no shell parses the value), values passed through shell-quote quote(), shell-escape or an escape function, values matched against an anchored regex or an isValid/isIP/isFQDN check in the lines above, constant commands and commands built only from local values, RegExp.exec and database exec methods, comments and string literals. VNX-NODE-003 reports exec/execSync with any run-time command string, whatever its source; this rule reports the subset where request data reaches it, across the wider set of shell-running APIs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-013/",
	"languages": ["node"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["command-injection", "child-process", "rce"],
}

_msg := "Shell command built from request input (OS command injection): shell metacharacters in it run attacker commands. Use execFile/spawn with an argument array and no shell, and validate the value against an allowlist"

_is_js(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies|payload)\b|\breq\.(?:param|get|header)\s*\(|\bctx\.(?:request\.)?(?:query|body|params|headers|querystring)\b`

_cp_mod := `['"](?:node:)?child_process['"]`

# Names the child_process module is bound to in this file.
_alias_res := [
	concat("", [`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*`, _cp_mod, `\s*\)`]),
	concat("", [`import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+`, _cp_mod]),
	concat("", [`import\s+([A-Za-z_$][\w$]*)\s+from\s+`, _cp_mod]),
]

_module_aliases(content) := {m[1] |
	some re in _alias_res
	some m in regex.find_all_string_submatch_n(re, content, -1)
}

# exec/execSync imported by name, and promisified wrappers of them.
_bare_names(content) := {n |
	some m in regex.find_all_string_submatch_n(concat("", [`\{([^}]*)\}\s*(?:=\s*require\(\s*|from\s+)`, _cp_mod]), content, -1)
	some item in split(m[1], ",")
	parts := regex.split(`\s*(?::|\bas\b)\s*`, trim_space(item))
	parts[0] in {"exec", "execSync"}
	n := trim_space(parts[count(parts) - 1])
	n != ""
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:util\.)?promisify\(\s*(?:[\w$]+\.|require\(\s*['"](?:node:)?child_process['"]\s*\)\.)?exec\s*\)`, content, -1)
}

_alt(names) := concat("|", [n | some n in names])

_shell_sinks(content) := s if {
	mods := _module_aliases(content) | {"child_process", "childProcess"}
	bare := _bare_names(content)
	base := [
		concat("", [`(?:^|[^\w$.])(?:`, _alt(mods), `)\.(?:exec|execSync)\s*\(`]),
		`\brequire\(\s*CHILD_PROCESS\s*\)\.(?:exec|execSync)\s*\(`,
		`(?:^|[^\w$.])(?:shell|shelljs|sh)\.exec\s*\(`,
		`(?:^|[^\w$.])(?:execa\.command|execa\.commandSync|execaCommand|execaCommandSync)\s*\(`,
	]
	s := _with_bare(base, bare)
}

_with_bare(base, bare) := base if count(bare) == 0

_with_bare(base, bare) := array.concat(base, [concat("", [`(?:^|[^\w$.])(?:`, _alt(bare), `)\s*\(`])]) if count(bare) > 0

_spawn_re := `(?:^|[^\w$])(?:spawn|spawnSync|execFile|execFileSync)\s*\(`

_file_gate := `child_process|shelljs|execa`

# A quoted string holding ${ is the inside of a template literal (`a '${x}'`)
# and is kept, so the interpolation stays visible.
_blank(s) := regex.replace(s, `'(?:[^'\\$]|\\.|\$[^{'])*'|"(?:[^"\\$]|\\.|\$[^{"])*"`, "''")

_opens(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The call's text after its opening parenthesis, continued over at most six
# further lines while its parentheses are open.
_call_text(lines, i, rest) := rest if _opens(rest) < 0

_call_text(lines, i, rest) := t if {
	_opens(rest) >= 0
	last := min([count(lines) - 1, i + 6])
	last >= i + 1
	t := concat(" ", array.concat([rest], array.slice(lines, i + 1, last + 1)))
}

_call_text(lines, i, rest) := rest if {
	_opens(rest) >= 0
	i + 1 > count(lines) - 1
}

# The first top-level argument; strings, template literals and bracketed
# groups (two levels deep) are taken whole.
_arg_re := "^(?:'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`(?:[^`\\\\]|\\\\.)*`|\\((?:[^()]|\\([^()]*\\))*\\)|\\[(?:[^\\[\\]]|\\[[^\\[\\]]*\\])*\\]|\\{(?:[^{}]|\\{[^{}]*\\})*\\}|[^,()\\[\\]{}'\"`])*"

_first_arg(t) := regex.find_n(_arg_re, trim_left(t, " \t"), 1)[0]

_refs(text, names) if {
	some n in names
	contains(text, n)
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `(?:\s*$|\s*[^\s:\w$])`]), text)
}

_binding(item) := v if {
	lhs := trim_space(split(item, "=")[0])
	parts := split(lhs, ":")
	v := trim_left(trim_space(parts[count(parts) - 1]), ".")
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

_destructured(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	contains(l, "{")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*(.*)$`, l, 1)
	count(m) > 0
	regex.match(_src, m[0][2])
	some item in split(m[0][1], ",")
	v := _binding(item)
}

# One further hop through an assignment that uses a tainted name, unless that
# assignment picks the value from a fixed list ([...].includes(x) ? x : y).
_tainted(lines, i) := t if {
	t1 := _direct(lines, i) | _destructured(lines, i)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		_refs(l, t1)
		v := helpers.assigned_first(l)
		not regex.match(`\]\s*\.includes\s*\(`, l)
	}
	t := t1 | t2
}

# Names assigned from a request value. A lookup keyed by one (a session
# fetched with req.cookies.token, a record found by req.params.id) returns
# server data, not the client's string.
_direct(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_src, l)
	not regex.match(_lookup_re, l)
	v := helpers.assigned_first(l)
}

_lookup_re := `=\s*(?:await\s+)?[\w.$?]+\.(?:get|findOne|findByPk|findById|findUnique|verify|decode|has)\(\s*(?:req|request|ctx)\b`

_reaches(a, _, _) if regex.match(_src, a)

_reaches(a, lines, i) if _refs(a, _tainted(lines, i))

_guard_re := `\bquote\s*\(|shell-?escape|\bescapeShell\w*\s*\(|\bshellEscape\s*\(|\bisValid\w*\s*\(|\bis(?:IP|FQDN|Alphanumeric|Int|UUID)\s*\(|/\^[^/\n]*\$/[gimsuy]*\.test\s*\(`

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 25, 0))

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# exec-style calls: the first argument is the shell command line.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	regex.match(_file_gate, content)
	sinks := _shell_sinks(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	code := _blank(regex.replace(line, `['"](?:node:)?child_process['"]`, "CHILD_PROCESS"))
	some sink in sinks
	regex.match(sink, code)
	parts := regex.split(sink, code)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _call_text(lines, i, rest)
	a := _first_arg(t)
	trim_space(a) != ""
	_reaches(a, lines, i)
	not _guarded(lines, i)
	finding := _finding(path, i, line)
}

# spawn/execFile run through a shell: shell: true, or sh/bash -c <script>.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	contains(content, "child_process")
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_spawn_re, _blank(line))
	parts := regex.split(_spawn_re, line)
	count(parts) > 1
	t := _call_text(lines, i, concat(" ", array.slice(parts, 1, count(parts))))
	_via_shell(t)
	_reaches(t, lines, i)
	not _guarded(lines, i)
	finding := _finding(path, i, line)
}

_via_shell(t) if regex.match(`\bshell\s*:\s*(?:true|['"][^'"]+['"])`, t)

_via_shell(t) if regex.match(`^\s*['"](?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?)['"]\s*,\s*\[\s*['"](?:-c|/c|-Command)['"]`, t)
